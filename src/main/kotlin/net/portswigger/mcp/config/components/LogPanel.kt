package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.logging.ExtensionLogger
import net.portswigger.mcp.logging.LogListenerHandle
import java.awt.BorderLayout
import javax.swing.*

class LogPanel : JPanel() {
    private val textArea = JTextArea().apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        font = Design.Typography.bodyMedium
    }
    private var listenerHandle: LogListenerHandle? = null

    init {
        layout = BorderLayout()
        updateColors()

        val scrollPane = JScrollPane(textArea).apply {
            border = null
            verticalScrollBar.unitIncrement = 16
        }

        val container = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            add(Design.createSectionLabel("MCP Activity Log"))
            add(Box.createVerticalStrut(Design.Spacing.MD))
            add(scrollPane)
        }

        add(container, BorderLayout.CENTER)

        startListening()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    private fun updateColors() {
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
    }

    private fun startListening() {
        textArea.text = ExtensionLogger.logs().joinToString("\n")
        listenerHandle = ExtensionLogger.addListener { line ->
            SwingUtilities.invokeLater {
                if (textArea.text.isNotEmpty()) textArea.append("\n")
                textArea.append(line)
                textArea.caretPosition = textArea.document.length
            }
        }
    }

    fun cleanup() {
        listenerHandle?.remove()
        listenerHandle = null
    }
}
