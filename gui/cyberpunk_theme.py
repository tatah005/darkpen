from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

# Color Palette
COLORS = {
    'background': '#0a0a0a',
    'panel_bg': '#1a1a1a',
    'text_primary': '#00ff9f',
    'text_secondary': '#00ccff',
    'electric_blue': '#00f6ff',
    'neon_green': '#00ff9f',
    'cyber_yellow': '#ffd319',
    'cyber_purple': '#ff00ff',
    'warning_red': '#ff0033',
    'red': '#ff0000'
}

# Font Configurations
FONTS = {
    'terminal': QFont('Consolas', 10),
    'heading': QFont('Segoe UI', 12, QFont.Bold),
    'body': QFont('Segoe UI', 10),
    'title': QFont('Segoe UI', 24, QFont.Bold)
}

# Layout Constants
LAYOUT = {
    'margin': 10,
    'padding': 15,
    'border_radius': 10
}

def get_styles():
    return {
        'terminal': f"""
            QTextEdit {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['neon_green']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: {LAYOUT['border_radius']}px;
                padding: {LAYOUT['padding']}px;
                font-family: {FONTS['terminal']};
            }}
        """,
        
        'input_fields': f"""
            QLineEdit {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: {LAYOUT['border_radius']}px;
                padding: 8px 15px;
                font-size: 14px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['neon_green']};
            }}
        """,
        
        'buttons': f"""
            QPushButton {{
                background-color: {COLORS['electric_blue']};
                color: {COLORS['background']};
                border: none;
                border-radius: {LAYOUT['border_radius']}px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['cyber_purple']};
            }}
            QPushButton:disabled {{
                background-color: {COLORS['panel_bg']};
                color: #666666;
            }}
        """,
        
        'combo_box': f"""
            QComboBox {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: {LAYOUT['border_radius']}px;
                padding: 8px 15px;
                font-size: 14px;
            }}
            QComboBox:hover {{
                border-color: {COLORS['neon_green']};
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox::down-arrow {{
                image: none;
                border: none;
            }}
        """,
        
        'table': f"""
            QTableWidget {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: {LAYOUT['border_radius']}px;
                gridline-color: {COLORS['electric_blue']};
            }}
            QTableWidget::item {{
                padding: 5px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['cyber_purple']};
            }}
            QHeaderView::section {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['electric_blue']};
                padding: 5px;
            }}
        """,
        
        'tree_widget': f"""
            QTreeWidget {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: {LAYOUT['border_radius']}px;
            }}
            QTreeWidget::item {{
                padding: 5px;
            }}
            QTreeWidget::item:selected {{
                background-color: {COLORS['cyber_purple']};
            }}
        """,
        
        'tab_widget': f"""
            QTabWidget::pane {{
                border: 2px solid {COLORS['electric_blue']};
                border-radius: {LAYOUT['border_radius']}px;
                top: -1px;
            }}
            QTabBar::tab {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-bottom: none;
                border-top-left-radius: {LAYOUT['border_radius']}px;
                border-top-right-radius: {LAYOUT['border_radius']}px;
                padding: 8px 15px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['cyber_purple']};
            }}
        """,
        
        'content_panel': f"""
            QFrame {{
                background-color: {COLORS['panel_bg']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: {LAYOUT['border_radius']}px;
                padding: {LAYOUT['padding']}px;
            }}
        """,
        
        'input_frame': f"""
            QFrame {{
                background-color: {COLORS['panel_bg']};
                border: 1px solid {COLORS['electric_blue']};
                border-radius: {LAYOUT['border_radius']}px;
                padding: {LAYOUT['padding']}px;
            }}
        """
    }

STYLES = get_styles()

# Styles
STYLES = {
    'main_window': f"""
        QMainWindow {{
            background-color: {COLORS['background']};
        }}
    """,
    
    'toolbar': f"""
        QToolBar {{
            background-color: {COLORS['panel_bg']};
            border-bottom: 2px solid {COLORS['electric_blue']};
            spacing: 10px;
            padding: 5px;
        }}
        QToolButton {{
            color: {COLORS['text_primary']};
            background-color: transparent;
            border: none;
            padding: 8px;
            margin: 0 5px;
            font-size: 14px;
        }}
        QToolButton:hover {{
            background-color: {COLORS['cyber_purple']};
            border-radius: 5px;
        }}
    """,
    
    'terminal': f"""
        QTextEdit {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['neon_green']};
            border: 2px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
            padding: {LAYOUT['padding']}px;
        }}
    """,
    
    'input_fields': f"""
        QLineEdit {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 2px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
            padding: 8px 15px;
            font-size: 14px;
        }}
        QLineEdit:focus {{
            border-color: {COLORS['neon_green']};
        }}
    """,
    
    'buttons': f"""
        QPushButton {{
            background-color: {COLORS['electric_blue']};
            color: {COLORS['background']};
            border: none;
            border-radius: {LAYOUT['border_radius']}px;
            padding: 10px 20px;
            font-weight: bold;
            font-size: 14px;
        }}
        QPushButton:hover {{
            background-color: {COLORS['cyber_purple']};
        }}
        QPushButton:disabled {{
            background-color: {COLORS['panel_bg']};
            color: #666666;
        }}
    """,
    
    'combo_box': f"""
        QComboBox {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 2px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
            padding: 8px 15px;
            font-size: 14px;
        }}
        QComboBox:hover {{
            border-color: {COLORS['neon_green']};
        }}
        QComboBox::drop-down {{
            border: none;
        }}
        QComboBox::down-arrow {{
            image: none;
            border: none;
        }}
    """,
    
    'table': f"""
        QTableWidget {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 2px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
            gridline-color: {COLORS['electric_blue']};
        }}
        QTableWidget::item {{
            padding: 5px;
        }}
        QTableWidget::item:selected {{
            background-color: {COLORS['cyber_purple']};
        }}
        QHeaderView::section {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['electric_blue']};
            padding: 5px;
        }}
    """,
    
    'tree_widget': f"""
        QTreeWidget {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 2px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
        }}
        QTreeWidget::item {{
            padding: 5px;
        }}
        QTreeWidget::item:selected {{
            background-color: {COLORS['cyber_purple']};
        }}
    """,
    
    'tab_widget': f"""
        QTabWidget::pane {{
            border: 2px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
            top: -1px;
        }}
        QTabBar::tab {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 2px solid {COLORS['electric_blue']};
            border-bottom: none;
            border-top-left-radius: {LAYOUT['border_radius']}px;
            border-top-right-radius: {LAYOUT['border_radius']}px;
            padding: 8px 15px;
            margin-right: 2px;
        }}
        QTabBar::tab:selected {{
            background-color: {COLORS['cyber_purple']};
        }}
    """,
    
    'content_panel': f"""
        QFrame {{
            background-color: {COLORS['panel_bg']};
            border: 2px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
            padding: {LAYOUT['padding']}px;
        }}
    """,
    
    'input_frame': f"""
        QFrame {{
            background-color: {COLORS['panel_bg']};
            border: 1px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
            padding: {LAYOUT['padding']}px;
        }}
    """,
    
    'calendar': f"""
        QCalendarWidget {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 2px solid {COLORS['electric_blue']};
            border-radius: {LAYOUT['border_radius']}px;
            padding: {LAYOUT['padding']}px;
        }}
        QCalendarWidget QToolButton {{
            color: {COLORS['text_primary']};
            background-color: transparent;
            border: none;
            border-radius: 5px;
            padding: 5px;
        }}
        QCalendarWidget QToolButton:hover {{
            background-color: {COLORS['cyber_purple']};
        }}
        QCalendarWidget QSpinBox {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['electric_blue']};
            border-radius: 3px;
            padding: 3px;
        }}
        QCalendarWidget QMenu {{
            background-color: {COLORS['panel_bg']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['electric_blue']};
        }}
        QCalendarWidget QMenu::item:selected {{
            background-color: {COLORS['cyber_purple']};
        }}
        QCalendarWidget QWidget#qt_calendar_navigationbar {{
            background-color: {COLORS['panel_bg']};
            border-top-left-radius: {LAYOUT['border_radius']}px;
            border-top-right-radius: {LAYOUT['border_radius']}px;
        }}
        QCalendarWidget QWidget#qt_calendar_prevmonth,
        QCalendarWidget QWidget#qt_calendar_nextmonth {{
            qproperty-icon: none;
            color: {COLORS['text_primary']};
            border: none;
            border-radius: 5px;
            padding: 5px;
        }}
        QCalendarWidget QWidget#qt_calendar_prevmonth:hover,
        QCalendarWidget QWidget#qt_calendar_nextmonth:hover {{
            background-color: {COLORS['cyber_purple']};
        }}
    """
}

# Font Configurations
FONTS = {
    'title': QFont('Arial', 24, QFont.Bold),
    'heading': 'Segoe UI, Arial, sans-serif',
    'body': 'Segoe UI, Arial, sans-serif',
    'terminal': 'Consolas, Monaco, monospace'
}

# Layout Constants
LAYOUT = {
    'margin': 10,
    'padding': 15,
    'border_radius': 10
} 