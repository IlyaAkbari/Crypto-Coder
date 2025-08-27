from PyQt6.QtWidgets import QComboBox
from PyQt6.QtCore import QSize

class AnimatedComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        # دسترسی به ویژگی‌های تم از والد
        while parent and not hasattr(parent, 'is_dark'):
            parent = parent.parent()
        self.is_dark = parent.is_dark if parent else True
        self.button_color = parent.custom_button_color if parent else "#4fc3f7"

        # تنظیم فونت و استایل
        self.setFont(self.font())
        self.apply_styles()

    def apply_styles(self):
        """اعمال استایل ساده و زیبا به ComboBox بر اساس تم."""
        if self.is_dark:
            stylesheet = f"""
                QComboBox {{
                    background-color: #2a2a3a;
                    color: #e0e0e0;
                    border: 1px solid #3a3a4a;
                    border-radius: 8px;
                    padding: 8px 30px 8px 12px;
                    font-family: 'Segoe UI', sans-serif;
                    font-size: 14px;
                }}
                QComboBox:hover {{
                    border: 2px solid {self.button_color};
                    background-color: #3a3a4a;
                }}
                QComboBox:focus {{
                    border: 2px solid {self.button_color};
                }}
                QComboBox::drop-down {{
                    border: none;
                    width: 30px;
                }}
                QComboBox::down-arrow {{
                    image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABmJLR0QA/wD/AP+gvaeTAAABWUlEQVRIx82Uz0sCURTH/5s3S5YsWbKkSZa0yZIlS9b8AyRbsmTJkiVbsmTJkiVLlmzJkiVbsmTJkiVbsmTJkiVbsmTJkiVLlizZ3+ecOXN3L3e4c+655557iIg4q9VqY2Njo1ar9Xg8Ho/HYrEYEXF4PB6LxeLxeDwWi8ViMcbj8XgsFovF4/F4LBaLxWLxeDwWi8VisVgsFovFYrFYLBZjfGtra0wmk8lkMvl8vmE2m82y2WzL5/Nms9n29va+vr7W1tZmMplMJpPJZDLZbDbZbLbb7X6/3+12u91ut9vtdrvdbrebzWaz2ez29va+vr6Ojo7JZDJZTBZjsVhMJpPJZDLZbLbb7Xa73W632+12u91ut9vtdrvdbrebzWaz2ez29va+vr6Ojo7JZDKZTCaTyWQymUwmk8lks9lutzvOZrPZbLfb7Xa73W632+12u91ut9vtdrvdbrebzWaz2eyc/wB0oJ5l2W5OAAAAAElFTkSuQmCC);
                    width: 16px;
                    height: 16px;
                }}
                QComboBox QAbstractItemView {{
                    background-color: #2a2a3a;
                    color: #e0e0e0;
                    selection-background-color: {self.button_color};
                    selection-color: #ffffff;
                    border: 1px solid #3a3a4a;
                    border-radius: 6px;
                    padding: 4px;
                }}
                QComboBox QAbstractItemView::item {{
                    padding: 8px;
                    min-height: 28px;
                }}
                QComboBox QAbstractItemView::item:hover {{
                    background-color: #3a3a4a;
                }}
            """
        else:
            stylesheet = f"""
                QComboBox {{
                    background-color: #ffffff;
                    color: #333333;
                    border: 1px solid #d0d0d5;
                    border-radius: 8px;
                    padding: 8px 30px 8px 12px;
                    font-family: 'Segoe UI', sans-serif;
                    font-size: 14px;
                }}
                QComboBox:hover {{
                    border: 2px solid {self.button_color};
                    background-color: #f0f0f5;
                }}
                QComboBox:focus {{
                    border: 2px solid {self.button_color};
                }}
                QComboBox::drop-down {{
                    border: none;
                    width: 30px;
                }}
                QComboBox::down-arrow {{
                    image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABmJLR0QA/wD/AP+gvaeTAAABWUlEQVRIx82Uz0sCURTH/5s3S5YsWbKkSZa0yZIlS9b8AyRbsmTJkiVbsmTJkiVLlmzJkiVbsmTJkiVbsmTJkiVbsmTJkiVLlizZ3+ecOXN3L3e4c+655557iIg4q9VqY2Njo1ar9Xg8Ho/HYrEYEXF4PB6LxeLxeDwWi8ViMcbj8XgsFovF4/F4LBaLxWLxeDwWi8VisVgsFovFYrFYLBZjfGtra0wmk8lkMvl8vmE2m82y2WzL5/Nms9n29va+vr7W1tZmMplMJpPJZDLZbDbZbLbb7X6/3+12u91ut9vtdrvdbrebzWaz2ez29va+vr6Ojo7JZDJZTBZjsVhMJpPJZDLZbLbb7Xa73W632+12u91ut9vtdrvdbrebzWaz2ez29va+vr6Ojo7JZDKZTCaTyWQymUwmk8lks9lutzvOZrPZbLfb7Xa73W632+12u91ut9vtdrvdbrebzWaz2eyc/wB0oJ5l2W5OAAAAAElFTkSuQmCC);
                    width: 16px;
                    height: 16px;
                }}
                QComboBox QAbstractItemView {{
                    background-color: #ffffff;
                    color: #333333;
                    selection-background-color: {self.button_color};
                    selection-color: #ffffff;
                    border: 1px solid #d0d0d5;
                    border-radius: 6px;
                    padding: 4px;
                }}
                QComboBox QAbstractItemView::item {{
                    padding: 8px;
                    min-height: 28px;
                }}
                QComboBox QAbstractItemView::item:hover {{
                    background-color: #e0e0e5;
                }}
            """
        self.setStyleSheet(stylesheet)

    def sizeHint(self):
        """ارائه اندازه پیشنهادی برای ComboBox."""
        return QSize(200, 40)
