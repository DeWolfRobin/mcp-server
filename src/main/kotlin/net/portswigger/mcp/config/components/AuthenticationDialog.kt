package net.portswigger.mcp.config.components

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.Swing
import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.security.AuthConfig
import net.portswigger.mcp.security.AuthToken
import net.portswigger.mcp.security.ClientCredentials
import java.awt.*
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.*
import javax.swing.Box.createVerticalStrut
import javax.swing.table.DefaultTableModel
import kotlin.concurrent.thread

class AuthenticationDialog(
    private val parent: Component?, private val authConfig: AuthConfig
) : JDialog(SwingUtilities.getWindowAncestor(parent), "Authentication Management", ModalityType.APPLICATION_MODAL) {

    companion object {
        private const val DIALOG_WIDTH = 800
        private const val DIALOG_HEIGHT = 600
        private const val TABLE_HEIGHT = 150
        private const val TOKEN_DISPLAY_LENGTH = 20
    }

    private val clientCredentialsTable: JTable
    private val activeTokensTable: JTable
    private val clientCredentialsModel: DefaultTableModel
    private val activeTokensModel: DefaultTableModel

    private val generateClientButton: JButton
    private val generateTokenButton: JButton
    private val deleteClientButton: JButton
    private val revokeTokenButton: JButton
    private val revokeAllTokensButton: JButton

    init {
        setupDialog()

        clientCredentialsModel = object : DefaultTableModel(
            arrayOf<Array<Any>>(), arrayOf("Client ID", "Name", "Created")
        ) {
            override fun isCellEditable(row: Int, column: Int) = false
        }
        clientCredentialsTable = JTable(clientCredentialsModel).apply {
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            font = Font(Font.MONOSPACED, Font.PLAIN, 12)
        }

        activeTokensModel = object : DefaultTableModel(
            arrayOf<Array<Any>>(), arrayOf("Token (partial)", "Client ID", "Created", "Expires", "Full Token")
        ) {
            override fun isCellEditable(row: Int, column: Int) = false
        }
        activeTokensTable = JTable(activeTokensModel).apply {
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            font = Font(Font.MONOSPACED, Font.PLAIN, 12)
            columnModel.getColumn(4).minWidth = 0
            columnModel.getColumn(4).maxWidth = 0
            columnModel.getColumn(4).width = 0
        }

        generateClientButton = Design.createFilledButton("Generate Client Credentials").apply {
            addActionListener { showGenerateClientDialog() }
        }

        generateTokenButton = Design.createFilledButton("Generate Token").apply {
            addActionListener { showGenerateTokenDialog() }
        }

        deleteClientButton = Design.createOutlinedButton("Delete Client").apply {
            addActionListener { deleteSelectedClient() }
            isEnabled = false
        }

        revokeTokenButton = Design.createOutlinedButton("Revoke Token").apply {
            addActionListener { revokeSelectedToken() }
            isEnabled = false
        }

        revokeAllTokensButton = Design.createOutlinedButton("Revoke All Tokens").apply {
            addActionListener { revokeAllTokens() }
        }

        clientCredentialsTable.selectionModel.addListSelectionListener {
            deleteClientButton.isEnabled = clientCredentialsTable.selectedRow >= 0
        }

        activeTokensTable.selectionModel.addListSelectionListener {
            revokeTokenButton.isEnabled = activeTokensTable.selectedRow >= 0
        }

        buildContent()
        refreshData()
    }

    private fun setupDialog() {
        defaultCloseOperation = DISPOSE_ON_CLOSE
        isResizable = true

        val escapeAction = object : AbstractAction() {
            override fun actionPerformed(e: ActionEvent?) {
                dispose()
            }
        }

        rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "escape"
        )
        rootPane.actionMap.put("escape", escapeAction)
    }

    private fun buildContent() {
        val contentPanel = JPanel().apply {
            layout = BorderLayout()
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.LG, Design.Spacing.LG, 0, Design.Spacing.LG
            )
        }

        val mainPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
        }

        val titleLabel = Design.createSectionLabel("Authentication Management").apply {
            alignmentX = LEFT_ALIGNMENT
        }
        mainPanel.add(titleLabel)
        mainPanel.add(createVerticalStrut(Design.Spacing.LG))

        val clientSection = createClientCredentialsSection()
        mainPanel.add(clientSection)
        mainPanel.add(createVerticalStrut(Design.Spacing.LG))

        val tokenSection = createActiveTokensSection()
        mainPanel.add(tokenSection)

        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT)).apply {
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.LG,
                Design.Spacing.LG,
                Design.Spacing.LG,
                Design.Spacing.LG
            )
        }

        val closeButton = Design.createFilledButton("Close").apply {
            addActionListener { dispose() }
        }
        buttonPanel.add(closeButton)

        contentPanel.add(mainPanel, BorderLayout.CENTER)
        contentPanel.add(buttonPanel, BorderLayout.SOUTH)
        contentPane = contentPanel
    }

    private fun createClientCredentialsSection(): JComponent {
        val panel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
                BorderFactory.createEmptyBorder(
                    Design.Spacing.MD,
                    Design.Spacing.MD,
                    Design.Spacing.MD,
                    Design.Spacing.MD
                )
            )
            alignmentX = LEFT_ALIGNMENT
        }

        val sectionLabel = Design.createSubsectionLabel("Client Credentials").apply {
            alignmentX = LEFT_ALIGNMENT
        }
        panel.add(sectionLabel)
        panel.add(createVerticalStrut(Design.Spacing.SM))

        val scrollPane = JScrollPane(clientCredentialsTable).apply {
            preferredSize = Dimension(0, TABLE_HEIGHT)
            alignmentX = LEFT_ALIGNMENT
        }
        panel.add(scrollPane)
        panel.add(createVerticalStrut(Design.Spacing.SM))

        val buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, 0)).apply {
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
            add(generateClientButton)
            add(deleteClientButton)
        }
        panel.add(buttonPanel)

        return panel
    }

    private fun createActiveTokensSection(): JComponent {
        val panel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
                BorderFactory.createEmptyBorder(
                    Design.Spacing.MD,
                    Design.Spacing.MD,
                    Design.Spacing.MD,
                    Design.Spacing.MD
                )
            )
            alignmentX = LEFT_ALIGNMENT
        }

        val sectionLabel = Design.createSubsectionLabel("Active Tokens").apply {
            alignmentX = LEFT_ALIGNMENT
        }
        panel.add(sectionLabel)
        panel.add(createVerticalStrut(Design.Spacing.SM))

        val scrollPane = JScrollPane(activeTokensTable).apply {
            preferredSize = Dimension(0, TABLE_HEIGHT)
            alignmentX = LEFT_ALIGNMENT
        }
        panel.add(scrollPane)
        panel.add(createVerticalStrut(Design.Spacing.SM))

        val buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, 0)).apply {
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
            add(generateTokenButton)
            add(revokeTokenButton)
            add(revokeAllTokensButton)
        }
        panel.add(buttonPanel)

        return panel
    }

    private fun showGenerateClientDialog() {
        val nameField = JTextField(20)

        val panel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JLabel("Client Name:"))
            add(nameField)
        }

        val result = JOptionPane.showConfirmDialog(
            this, panel, "Generate Client Credentials", JOptionPane.OK_CANCEL_OPTION
        )

        if (result == JOptionPane.OK_OPTION) {
            val name = nameField.text.trim()

            if (name.isNotEmpty()) {
                thread {
                    try {
                        val credentials = authConfig.generateClientCredentials(name)
                        CoroutineScope(Dispatchers.Swing).launch {
                            refreshData()
                            showCredentialsDialog(credentials)
                        }
                    } catch (e: Exception) {
                        CoroutineScope(Dispatchers.Swing).launch {
                            Dialogs.showMessageDialog(
                                this@AuthenticationDialog,
                                "Failed to generate client credentials: ${e.message}",
                                JOptionPane.ERROR_MESSAGE
                            )
                        }
                    }
                }
            } else {
                Dialogs.showMessageDialog(
                    this, "Client name is required", JOptionPane.ERROR_MESSAGE
                )
            }
        }
    }

    private fun showCredentialsDialog(credentials: ClientCredentials) {
        showCredentialsDetailsDialog(
            title = "Client Credentials Generated",
            clientId = credentials.clientId,
            clientSecret = credentials.clientSecret,
            name = credentials.name
        )
    }

    private fun showGenerateTokenDialog() {
        val clients = authConfig.listClients().filter { it.enabled }
        if (clients.isEmpty()) {
            Dialogs.showMessageDialog(
                this,
                "No enabled client credentials found. Generate client credentials first.",
                JOptionPane.WARNING_MESSAGE
            )
            return
        }

        val clientCombo = JComboBox(clients.map { "${it.name} (${it.clientId})" }.toTypedArray())

        val panel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JLabel("Select Client:"))
            add(clientCombo)
        }

        val result = JOptionPane.showConfirmDialog(
            this, panel, "Generate Token", JOptionPane.OK_CANCEL_OPTION
        )

        if (result == JOptionPane.OK_OPTION) {
            val selectedClient = clients[clientCombo.selectedIndex]
            thread {
                try {
                    val token = authConfig.generateToken(selectedClient.clientId, selectedClient.clientSecret)
                    CoroutineScope(Dispatchers.Swing).launch {
                        if (token != null) {
                            refreshData()
                            showTokenDialog(token)
                        } else {
                            Dialogs.showMessageDialog(
                                this@AuthenticationDialog,
                                "Failed to generate token. Check client credentials.",
                                JOptionPane.ERROR_MESSAGE
                            )
                        }
                    }
                } catch (e: Exception) {
                    CoroutineScope(Dispatchers.Swing).launch {
                        Dialogs.showMessageDialog(
                            this@AuthenticationDialog,
                            "Failed to generate token: ${e.message}",
                            JOptionPane.ERROR_MESSAGE
                        )
                    }
                }
            }
        }
    }

    private fun showTokenDialog(token: AuthToken) {
        showTokenDetailsDialog(
            title = "Access Token Generated", token = token.token, clientId = token.clientId
        )
    }

    private fun deleteSelectedClient() {
        val selectedRow = clientCredentialsTable.selectedRow
        if (selectedRow >= 0) {
            val clientId = clientCredentialsModel.getValueAt(selectedRow, 0) as String
            val clientName = clientCredentialsModel.getValueAt(selectedRow, 1) as String

            val result = Dialogs.showConfirmDialog(
                this,
                "Delete client '$clientName' ($clientId)?\nThis will permanently remove the client and revoke all its tokens.",
                JOptionPane.YES_NO_OPTION
            )

            if (result == JOptionPane.YES_OPTION) {
                thread {
                    try {
                        authConfig.revokeAllTokensForClient(clientId)
                        val success = authConfig.deleteClient(clientId)
                        CoroutineScope(Dispatchers.Swing).launch {
                            if (success) {
                                refreshData()
                                Dialogs.showMessageDialog(
                                    this@AuthenticationDialog,
                                    "Client deleted successfully",
                                    JOptionPane.INFORMATION_MESSAGE
                                )
                            } else {
                                Dialogs.showMessageDialog(
                                    this@AuthenticationDialog, "Failed to delete client", JOptionPane.ERROR_MESSAGE
                                )
                            }
                        }
                    } catch (e: Exception) {
                        CoroutineScope(Dispatchers.Swing).launch {
                            Dialogs.showMessageDialog(
                                this@AuthenticationDialog,
                                "Failed to delete client: ${e.message}",
                                JOptionPane.ERROR_MESSAGE
                            )
                        }
                    }
                }
            }
        }
    }

    private fun revokeSelectedToken() {
        val selectedRow = activeTokensTable.selectedRow
        if (selectedRow >= 0) {
            val fullToken = activeTokensModel.getValueAt(selectedRow, 4) as String
            val tokenDisplay = activeTokensModel.getValueAt(selectedRow, 0) as String

            val result = Dialogs.showConfirmDialog(
                this, "Revoke token $tokenDisplay?", JOptionPane.YES_NO_OPTION
            )

            if (result == JOptionPane.YES_OPTION) {
                thread {
                    try {
                        val success = authConfig.revokeToken(fullToken)
                        CoroutineScope(Dispatchers.Swing).launch {
                            if (success) {
                                refreshData()
                                Dialogs.showMessageDialog(
                                    this@AuthenticationDialog,
                                    "Token revoked successfully",
                                    JOptionPane.INFORMATION_MESSAGE
                                )
                            } else {
                                Dialogs.showMessageDialog(
                                    this@AuthenticationDialog, "Failed to revoke token", JOptionPane.ERROR_MESSAGE
                                )
                            }
                        }
                    } catch (e: Exception) {
                        CoroutineScope(Dispatchers.Swing).launch {
                            Dialogs.showMessageDialog(
                                this@AuthenticationDialog,
                                "Failed to revoke token: ${e.message}",
                                JOptionPane.ERROR_MESSAGE
                            )
                        }
                    }
                }
            }
        }
    }

    private fun revokeAllTokens() {
        val result = Dialogs.showConfirmDialog(
            this, "Revoke ALL active tokens?\nThis will invalidate all current sessions.", JOptionPane.YES_NO_OPTION
        )

        if (result == JOptionPane.YES_OPTION) {
            thread {
                try {
                    val tokens = authConfig.listActiveTokens()
                    tokens.forEach { authConfig.revokeToken(it.token) }
                    CoroutineScope(Dispatchers.Swing).launch {
                        refreshData()
                        Dialogs.showMessageDialog(
                            this@AuthenticationDialog,
                            "All tokens revoked successfully (${tokens.size} tokens)",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                    }
                } catch (e: Exception) {
                    CoroutineScope(Dispatchers.Swing).launch {
                        Dialogs.showMessageDialog(
                            this@AuthenticationDialog,
                            "Failed to revoke tokens: ${e.message}",
                            JOptionPane.ERROR_MESSAGE
                        )
                    }
                }
            }
        }
    }

    private fun refreshData() {
        thread {
            try {
                val clients = authConfig.listClients().filter { it.enabled }
                val tokens = authConfig.listActiveTokens()

                CoroutineScope(Dispatchers.Swing).launch {
                    clientCredentialsModel.rowCount = 0
                    clients.forEach { client ->
                        val createdTime = Instant.ofEpochSecond(client.createdAt).atZone(ZoneId.systemDefault())
                            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))

                        clientCredentialsModel.addRow(
                            arrayOf(
                                client.clientId, client.name, createdTime
                            )
                        )
                    }

                    activeTokensModel.rowCount = 0
                    tokens.forEach { token ->
                        val createdTime = Instant.ofEpochSecond(token.createdAt).atZone(ZoneId.systemDefault())
                            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))

                        val expiresTime = Instant.ofEpochSecond(token.expiresAt).atZone(ZoneId.systemDefault())
                            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))

                        val displayToken = if (token.token.length > TOKEN_DISPLAY_LENGTH) {
                            "${token.token.take(TOKEN_DISPLAY_LENGTH)}..."
                        } else {
                            token.token
                        }

                        activeTokensModel.addRow(
                            arrayOf(
                                displayToken,
                                token.clientId,
                                createdTime,
                                expiresTime,
                                token.token
                            )
                        )
                    }
                }
            } catch (e: Exception) {
                CoroutineScope(Dispatchers.Swing).launch {
                    Dialogs.showMessageDialog(
                        this@AuthenticationDialog,
                        "Failed to refresh authentication data: ${e.message}",
                        JOptionPane.ERROR_MESSAGE
                    )
                }
            }
        }
    }

    private fun showCredentialsDetailsDialog(title: String, clientId: String, clientSecret: String, name: String) {
        val dialog = JDialog(this, title, true)
        dialog.defaultCloseOperation = DISPOSE_ON_CLOSE

        val contentPanel = JPanel().apply {
            layout = BorderLayout()
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG
            )
        }

        val mainPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
        }

        val successLabel = JLabel("Client credentials generated successfully!").apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            alignmentX = LEFT_ALIGNMENT
        }
        mainPanel.add(successLabel)
        mainPanel.add(createVerticalStrut(Design.Spacing.LG))

        mainPanel.add(createCopyableRow("Client ID:", clientId))
        mainPanel.add(createVerticalStrut(Design.Spacing.LG))

        mainPanel.add(createCopyableRow("Client Secret:", clientSecret))
        mainPanel.add(createVerticalStrut(Design.Spacing.LG))

        mainPanel.add(createCopyableRow("Name:", name))
        mainPanel.add(createVerticalStrut(Design.Spacing.XL))

        val warningLabel =
            JLabel("IMPORTANT: Save these credentials now. The client secret will not be shown again.").apply {
                font = Design.Typography.bodyMedium
                foreground = Design.Colors.warning
                alignmentX = LEFT_ALIGNMENT
            }
        mainPanel.add(warningLabel)
        mainPanel.add(createVerticalStrut(Design.Spacing.XL))

        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT)).apply {
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(Design.Spacing.MD, 0, 0, 0)
        }

        val closeButton = Design.createFilledButton("Close").apply {
            addActionListener { dialog.dispose() }
        }
        buttonPanel.add(closeButton)

        contentPanel.add(mainPanel, BorderLayout.CENTER)
        contentPanel.add(buttonPanel, BorderLayout.SOUTH)

        dialog.contentPane = contentPanel
        dialog.size = Dimension(650, 380)
        dialog.setLocationRelativeTo(this)
        dialog.isVisible = true
    }

    private fun showTokenDetailsDialog(title: String, token: String, clientId: String) {
        val dialog = JDialog(this, title, true)
        dialog.defaultCloseOperation = DISPOSE_ON_CLOSE

        val contentPanel = JPanel().apply {
            layout = BorderLayout()
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG
            )
        }

        val mainPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
        }

        val successLabel = JLabel("Access token generated successfully!").apply {
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            alignmentX = LEFT_ALIGNMENT
        }
        mainPanel.add(successLabel)
        mainPanel.add(createVerticalStrut(Design.Spacing.LG))

        mainPanel.add(createCopyableRow("Client ID:", clientId))
        mainPanel.add(createVerticalStrut(Design.Spacing.LG))

        mainPanel.add(createCopyableRow("Token:", token))
        mainPanel.add(createVerticalStrut(Design.Spacing.XL))

        val warningLabel = JLabel("IMPORTANT: Save this token now. It will not be shown again.").apply {
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.warning
            alignmentX = LEFT_ALIGNMENT
        }
        mainPanel.add(warningLabel)
        mainPanel.add(createVerticalStrut(Design.Spacing.XL))

        val buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT)).apply {
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(Design.Spacing.MD, 0, 0, 0)
        }

        val closeButton = Design.createFilledButton("Close").apply {
            addActionListener { dialog.dispose() }
        }
        buttonPanel.add(closeButton)

        contentPanel.add(mainPanel, BorderLayout.CENTER)
        contentPanel.add(buttonPanel, BorderLayout.SOUTH)

        dialog.contentPane = contentPanel
        dialog.size = Dimension(650, 330)
        dialog.setLocationRelativeTo(this)
        dialog.isVisible = true
    }

    private fun createCopyableRow(label: String, value: String): JPanel {
        val panel = JPanel().apply {
            layout = BorderLayout(Design.Spacing.MD, 0)
            background = Design.Colors.surface
            alignmentX = LEFT_ALIGNMENT
            preferredSize = Dimension(600, 40)
            maximumSize = Dimension(Int.MAX_VALUE, 40)
        }

        val labelComponent = JLabel(label).apply {
            font = Design.Typography.labelLarge
            foreground = Design.Colors.onSurface
            preferredSize = Dimension(80, 32)
        }

        val valueField = JTextField(value).apply {
            isEditable = false
            font = Font(Font.MONOSPACED, Font.PLAIN, 12)
            background = Design.Colors.listBackground
            foreground = Design.Colors.onSurface
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.outline, 1), BorderFactory.createEmptyBorder(6, 10, 6, 10)
            )
            preferredSize = Dimension(400, 32)
        }

        val copyButton = Design.createOutlinedButton("Copy").apply {
            preferredSize = Dimension(80, 32)
            minimumSize = Dimension(80, 32)
            addActionListener {
                copyToClipboard(value, this)
            }
        }

        panel.add(labelComponent, BorderLayout.WEST)
        panel.add(valueField, BorderLayout.CENTER)
        panel.add(copyButton, BorderLayout.EAST)

        return panel
    }

    private fun copyToClipboard(text: String, button: JButton) {
        try {
            val clipboard = Toolkit.getDefaultToolkit().systemClipboard
            val stringSelection = java.awt.datatransfer.StringSelection(text)
            clipboard.setContents(stringSelection, null)

            val originalText = button.text
            button.text = "Copied!"
            button.isEnabled = false

            Timer(1500) {
                button.text = originalText
                button.isEnabled = true
            }.apply {
                isRepeats = false
                start()
            }
        } catch (e: Exception) {
            Dialogs.showMessageDialog(
                this, "Failed to copy to clipboard: ${e.message}", JOptionPane.ERROR_MESSAGE
            )
        }
    }

    fun showDialog() {
        pack()
        setLocationRelativeTo(parent)
        preferredSize = Dimension(DIALOG_WIDTH, DIALOG_HEIGHT)
        size = preferredSize
        isVisible = true
    }
}