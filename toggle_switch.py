from PyQt6.QtWidgets import QWidget
from PyQt6.QtGui import QPainter, QBrush, QColor, QPainterPath
from PyQt6.QtCore import Qt, QPropertyAnimation, QSize, QEasingCurve, pyqtProperty

class ToggleSwitch(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(60, 30)
        self.checked = parent.is_dark if parent and hasattr(parent, 'is_dark') else False
        self._circle_pos = 34 if self.checked else 4
        self._background_color = QColor(parent.button_color if parent and hasattr(parent, 'button_color') else "#4fc3f7") if self.checked else QColor("#4a4a4a")

        self.pos_animation = QPropertyAnimation(self, b"circle_pos")
        self.pos_animation.setDuration(300)
        self.pos_animation.setEasingCurve(QEasingCurve.Type.InOutCubic)

        self.color_animation = QPropertyAnimation(self, b"background_color")
        self.color_animation.setDuration(300)
        self.color_animation.setEasingCurve(QEasingCurve.Type.InOutCubic)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width(), self.height(), 15, 15)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(self._background_color))
        painter.drawPath(path)

        painter.setBrush(QBrush(QColor("#ffffff")))
        painter.drawEllipse(int(self._circle_pos), 4, 22, 22)

    def mousePressEvent(self, event):
        self.checked = not self.checked
        self.pos_animation.setStartValue(self._circle_pos)
        self.pos_animation.setEndValue(34 if self.checked else 4)
        parent = self.parent()
        button_color = parent.button_color if parent and hasattr(parent, 'button_color') else "#4fc3f7"
        self.color_animation.setStartValue(self._background_color)
        self.color_animation.setEndValue(QColor(button_color) if self.checked else QColor("#4a4a4a"))
        self.pos_animation.start()
        self.color_animation.start()
        while parent and not hasattr(parent, 'toggle_theme'):
            parent = parent.parent()
        if parent and hasattr(parent, 'toggle_theme'):
            parent.toggle_theme()

    def sizeHint(self):
        return QSize(60, 30)

    @pyqtProperty(float)
    def circle_pos(self):
        return self._circle_pos

    @circle_pos.setter
    def circle_pos(self, value):
        self._circle_pos = value
        self.update()

    @pyqtProperty(QColor)
    def background_color(self):
        return self._background_color

    @background_color.setter
    def background_color(self, value):
        self._background_color = value
        self.update()

    def update_styles(self):
        """به‌روزرسانی استایل‌های سوئیچ"""
        parent = self.parent()
        button_color = parent.button_color if parent and hasattr(parent, 'button_color') else "#4fc3f7"
        self._background_color = QColor(button_color) if self.checked else QColor("#4a4a4a")
        self._circle_pos = 34 if self.checked else 4
        self.update()