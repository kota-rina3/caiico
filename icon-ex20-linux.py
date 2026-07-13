import sys, os, struct, pefile, subprocess
from io import BytesIO
#from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QGridLayout, QScrollArea,
    QSizePolicy, QMessageBox, QProgressBar, QDialog, QComboBox,
    QCheckBox, QGroupBox, QDialogButtonBox, QTextEdit)
from PyQt6.QtGui import QIcon, QPixmap, QImage, QPainter, QDesktopServices
from PyQt6.QtCore import Qt, QUrl, QTimer, QTranslator, QSize
from PIL import Image

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class IconExtractor:
    """图标提取器 - 优化版"""

    @staticmethod
    def extract_icons_from_exe(exe_path, progress_callback=None):
        """使用 pefile 从 .exe 或 .dll 文件中提取所有图标资源"""
        icons = []

        try:
            pe = pefile.PE(exe_path)

            # 检查资源目录是否存在
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                print("没有找到资源目录")
                return icons

            if progress_callback:
                progress_callback(10, "解析资源目录...")

            # 收集所有图标资源
            icon_resources = []   # RT_ICON
            group_icons = []       # RT_GROUP_ICON

            RT_GROUP_ICON = pefile.RESOURCE_TYPE['RT_GROUP_ICON']
            RT_ICON = pefile.RESOURCE_TYPE['RT_ICON']

            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.struct.Id == RT_GROUP_ICON:
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            try:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                # 使用 get_data 只读取所需数据，避免加载整个文件
                                data = pe.get_data(data_rva, size)
                                group_icons.append({
                                    'id': resource_id.struct.Id,
                                    'data': data
                                })
                            except Exception as e:
                                print(f"获取组图标资源时出错: {e}")

                elif resource_type.struct.Id == RT_ICON:
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            try:
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                data = pe.get_data(data_rva, size)
                                icon_resources.append({
                                    'id': resource_id.struct.Id,
                                    'data': data,
                                    'size': size
                                })
                            except Exception as e:
                                print(f"获取图标资源时出错: {e}")

            if progress_callback:
                progress_callback(30, "处理图标资源...")

            # 如果没有找到组图标，直接处理单个图标资源
            if not group_icons:
                return IconExtractor._process_single_icons(icon_resources, progress_callback)

            # 处理组图标
            return IconExtractor._process_group_icons(group_icons, icon_resources, progress_callback)

        except pefile.PEFormatError as e:
            print(f"PE 格式错误: {e}")
        except Exception as e:
            print(f"解析PE文件时出错: {e}")

        return icons

    @staticmethod
    def _process_single_icons(icon_resources, progress_callback=None):
        """处理单个图标资源（无组信息时）"""
        icons = []
        total = len(icon_resources)

        for idx, icon_res in enumerate(icon_resources):
            try:
                # 尝试直接加载为 QPixmap
                pixmap = QPixmap()
                if pixmap.loadFromData(icon_res['data']):
                    size_str = f"{pixmap.width()}x{pixmap.height()}"
                    icons.append((pixmap, size_str))
                else:
                    # 备用：使用 PIL 构建 ICO 数据
                    ico_data = IconExtractor._build_ico_data(icon_res['data'])

                    img = Image.open(BytesIO(ico_data))
                    img = img.convert("RGBA")
                    qimage = QImage(img.tobytes(), img.width, img.height,
                                    QImage.Format.Format_RGBA8888)
                    pixmap = QPixmap.fromImage(qimage)
                    size_str = f"{img.width}x{img.height}"
                    icons.append((pixmap, size_str))

                # 每处理 5 个图标更新一次进度
                if progress_callback and idx % 5 == 0 and total > 0:
                    progress = 30 + int(50 * (idx + 1) / total)
                    progress_callback(progress, f"处理图标 {idx+1}/{total}")

            except Exception as e:
                print(f"处理单个图标资源时出错: {e}")

        return icons

    @staticmethod
    def _process_group_icons(group_icons, icon_resources, progress_callback=None):
        """处理组图标，串行转换以避免线程开销"""
        icons = []
        icon_dict = {res['id']: res for res in icon_resources}
        total_groups = len(group_icons)

        for group_idx, group in enumerate(group_icons):
            try:
                group_data = group['data']
                if len(group_data) < 6:
                    continue

                reserved, type_val, count = struct.unpack('<HHH', group_data[:6])
                if reserved != 0 or type_val != 1:
                    continue

                # 更新组处理进度
                if progress_callback and total_groups > 0:
                    group_progress = 30 + int(30 * group_idx / total_groups)
                    progress_callback(group_progress, f"处理图标组 {group_idx+1}/{total_groups}")

                # 解析并串行处理每个条目
                entry_size = 14
                for i in range(count):
                    entry_offset = 6 + i * entry_size
                    if entry_offset + entry_size > len(group_data):
                        break
                    entry_data = group_data[entry_offset:entry_offset+entry_size]
                    result = IconExtractor._process_icon_entry(entry_data, icon_dict)
                    if result:
                        icons.extend(result)

                    # 每处理 5 个图标更新一次进度
                    if progress_callback and i % 5 == 0:
                        icon_progress = 60 + int(20 * (i + 1) / count)
                        progress_callback(icon_progress, f"处理图标 {i+1}/{count}")

            except Exception as e:
                print(f"处理图标组时出错: {e}")

        return icons

    @staticmethod
    def _process_icon_entry(entry_data, icon_dict):
        """处理单个图标条目（返回图标列表，可能为空）"""
        icons = []
        try:
            width, height, colors, reserved, planes, bit_count, size, id_val = struct.unpack(
                '<BBBBHHIH', entry_data
            )

            width = 256 if width == 0 else width
            height = 256 if height == 0 else height

            if id_val in icon_dict:
                icon_data = icon_dict[id_val]['data']

                # 直接尝试加载为 QPixmap
                pixmap = QPixmap()
                if pixmap.loadFromData(icon_data):
                    size_str = f"{pixmap.width()}x{pixmap.height()}"
                    icons.append((pixmap, size_str))
                else:
                    # 备用：构建 ICO 数据
                    ico_data = IconExtractor._build_ico_data(
                        icon_data, width=width, height=height,
                        colors=colors, planes=planes, bit_count=bit_count)

                    img = Image.open(BytesIO(ico_data))
                    img = img.convert("RGBA")
                    qimage = QImage(img.tobytes(), img.width, img.height,
                                    QImage.Format.Format_RGBA8888)
                    pixmap = QPixmap.fromImage(qimage)
                    size_str = f"{img.width}x{img.height}"
                    icons.append((pixmap, size_str))

        except Exception as e:
            print(f"处理图标条目时出错: {e}")

        return icons

    @staticmethod
    def _build_ico_data(icon_data, width=32, height=32, colors=0, planes=1, bit_count=32):
        """构建完整的 ICO 数据(头部 + 图像数据)"""
        write_width = min(width, 255)
        write_height = min(height, 255)
        header = struct.pack('<HHH', 0, 1, 1)
        header += struct.pack('<BBBBHHII',
                              write_width, write_height, colors, 0,
                              planes, bit_count, len(icon_data), 22)
        return header + icon_data

    @staticmethod
    def extract_icons_from_ico(ico_path, progress_callback=None):
        """使用 PIL 从 ICO 文件中提取所有图标（串行处理）"""
        icons = []
        try:
            img = Image.open(ico_path)
            total_frames = getattr(img, 'n_frames', 1)

            for i in range(total_frames):
                try:
                    img.seek(i)
                    rgba_img = img.convert("RGBA")
                    qimage = QImage(rgba_img.tobytes(), rgba_img.width, rgba_img.height,
                                    QImage.Format.Format_RGBA8888)
                    pixmap = QPixmap.fromImage(qimage)
                    size_str = f"{rgba_img.width}x{rgba_img.height}"
                    icons.append((pixmap, size_str))

                    # 每处理一帧更新进度
                    if progress_callback and total_frames > 0:
                        progress = 30 + int(70 * (i + 1) / total_frames)
                        progress_callback(progress, f"处理帧 {i+1}/{total_frames}")
                except Exception as e:
                    print(f"处理 ICO 帧 {i} 时出错: {e}")

        except Exception as e:
            print(f"打开 ICO 文件时出错: {e}")

        # 去重：移除相同尺寸的图标
        unique_icons = []
        seen_sizes = set()
        for pixmap, size_str in icons:
            if size_str not in seen_sizes:
                unique_icons.append((pixmap, size_str))
                seen_sizes.add(size_str)

        return unique_icons


class ExportOptionsDialog(QDialog):
    """导出选项对话框 - 支持多格式批量导出"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("批量导出设置")
        self.setMinimumSize(350, 200)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # 格式选择
        format_group = QGroupBox("导出格式")
        format_layout = QVBoxLayout()
        format_layout.setSpacing(10)

        self.png_check = QCheckBox("PNG 格式 (透明背景)")
        self.png_check.setChecked(True)
        format_layout.addWidget(self.png_check)

        self.jpg_check = QCheckBox("JPG 格式 (白色背景)")
        self.jpg_check.setChecked(False)
        format_layout.addWidget(self.jpg_check)

        self.ico_check = QCheckBox("ICO 格式 (单尺寸图标)")
        self.ico_check.setChecked(False)
        format_layout.addWidget(self.ico_check)

        # 说明标签
        note_label = QLabel("选择要导出的格式，每种格式会创建单独的文件夹")
        note_label.setStyleSheet("color: #888888; font-style: italic; font-size: 11px;")
        note_label.setWordWrap(True)
        format_layout.addWidget(note_label)

        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        # 按钮
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.adjustSize()

    def get_export_options(self):
        """获取导出选项"""
        return {
            'export_png': self.png_check.isChecked(),
            'export_jpg': self.jpg_check.isChecked(),
            'export_ico': self.ico_check.isChecked()
        }


class AboutDialog(QDialog):
    """关于对话框"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于")
        self.setMinimumSize(500, 430)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # 标题
        title_label = QLabel("採图标")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 15px;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        # 版本信息
        version_label = QLabel("版本: 20.01.21")
        version_label.setStyleSheet("font-size: 14px; margin-bottom: 10px;")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version_label)

        # 描述
        description = QLabel("此工具可从 EXE 和 DLL 文件中提取图标，支持多尺寸（批量）导出。")
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description.setStyleSheet("margin-bottom: 20px;")
        layout.addWidget(description)

        # 特性列表
        features = QTextEdit()
        features.setReadOnly(True)
        features.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        features.setHtml("""
            <h3>主要功能：</h3>
            <ul>
                <li>从 EXE 和 DLL 文件中提取图标</li>
                <li>预览所有可用尺寸图标</li>
                <li>导出为 PNG、JPG 和 ICO 格式（单图标）</li>
                <li>批量导出为 PNG、JPG 和 ICO 格式</li>
            </ul>
        """)
        features.setStyleSheet("background-color: transparent; border: none;")
        layout.addWidget(features)

        # 跳转按钮
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(20, 10, 20, 10)

        self.tg = QPushButton("来 TG 找我玩!")
        self.tg.setFixedHeight(30)
        self.tg.clicked.connect(self.otohime)
        button_layout.addWidget(self.tg)

        self.hks = QPushButton("来保健室玩")
        self.hks.setFixedHeight(30)
        self.hks.clicked.connect(self.hokeshi)
        button_layout.addWidget(self.hks)

        self.deepin = QPushButton("去深度商店更新")
        self.deepin.setFixedHeight(30)
        self.deepin.clicked.connect(self.deepin_store)
        button_layout.addWidget(self.deepin)
        
        self.spark = QPushButton("去星火应用商店更新")
        self.spark.setFixedHeight(30)
        self.spark.clicked.connect(self.spark_store)
        button_layout.addWidget(self.spark)

        layout.addLayout(button_layout)

        # 版权信息
        copyright_label = QLabel("\u00a9 2023-2026 校医软件室 All rights reserved.")
        copyright_label.setStyleSheet("font-size: 12px; color: gray; margin-top: 15px;")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(copyright_label)

        self.adjustSize()

    def otohime(self):
        QDesktopServices.openUrl(QUrl("https://t.me/otohime_soft_room/42"))

    def hokeshi(self):
        QDesktopServices.openUrl(QUrl("https://github.com/kota-rina3/hokeshi"))

    def deepin_store(self):
        """打开作者主页"""
        subprocess.Popen(['deepin-home-appstore-client', 'appstore://deepin-home-appstore-client?app_detail_info/otohime.cai.ico'])

    def spark_store(self):
        subprocess.Popen(['spark-store', 'spk://store/tools/otohime.cai.ico'])

    


class IconExtractorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("採图标")
        self.setWindowIcon(QIcon(os.path.join(_SCRIPT_DIR, "cai_ico.ico")))
        self.setMinimumSize(970, 560)

        # 当前主题 (0=深色, 1=浅色) - 默认浅色
        self.current_theme = 1
        self.current_icons = []
        self.current_file = ""
        self.sort_direction = Qt.SortOrder.AscendingOrder  # 默认升序
        self.sort_by = "area"  # 默认按面积排序

        # 启用拖拽
        self.setAcceptDrops(True)

        self.init_ui()
        self.apply_light_theme()

    def init_ui(self):
        """初始化 UI"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # 顶部控制区域
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)

        # 主题切换
        self.theme_button = QPushButton("切换深色主题")
        self.theme_button.setFixedSize(120, 30)
        self.theme_button.clicked.connect(self.toggle_theme)
        control_layout.addWidget(self.theme_button)

        # 排序控件
        sort_layout = QHBoxLayout()
        sort_layout.setSpacing(5)

        sort_label = QLabel("排序:")
        sort_label.setFixedSize(30, 30)
        sort_layout.addWidget(sort_label)

        self.sort_combo = QComboBox()
        self.sort_combo.setFixedSize(120, 30)
        self.sort_combo.addItems(["按尺寸", "按宽度", "按高度", "按面积"])
        self.sort_combo.setCurrentText("按面积")
        self.sort_combo.currentTextChanged.connect(self.on_sort_changed)
        sort_layout.addWidget(self.sort_combo)

        self.direction_combo = QComboBox()
        self.direction_combo.setFixedSize(80, 30)
        self.direction_combo.addItems(["升序", "降序"])
        self.direction_combo.setCurrentText("升序")
        self.direction_combo.currentTextChanged.connect(self.on_direction_changed)
        sort_layout.addWidget(self.direction_combo)

        control_layout.addLayout(sort_layout)

        # 文件标签
        self.file_label = QLabel("未选择文件 - 可拖拽文件到窗口")
        self.file_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        control_layout.addWidget(self.file_label)

        # 选择文件
        self.select_button = QPushButton("选择文件")
        self.select_button.setFixedSize(100, 30)
        self.select_button.clicked.connect(self.select_file)
        control_layout.addWidget(self.select_button)

        # 批量导出
        self.save_all_button = QPushButton("批量导出")
        self.save_all_button.setFixedSize(100, 30)
        self.save_all_button.setEnabled(False)  # 初始禁用
        self.save_all_button.clicked.connect(self.save_all_icons)
        control_layout.addWidget(self.save_all_button)

        # 清除按钮
        self.clear_button = QPushButton("清除")
        self.clear_button.setFixedSize(80, 30)
        self.clear_button.clicked.connect(self.clear_all)
        control_layout.addWidget(self.clear_button)

        # 关于
        self.about_button = QPushButton("关于")
        self.about_button.setFixedSize(80, 30)
        self.about_button.clicked.connect(self.show_about)
        control_layout.addWidget(self.about_button)

        main_layout.addLayout(control_layout)

        # 进度条和状态标签
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(5)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("")
        self.progress_label.setVisible(False)
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_label.setStyleSheet("color: #666666; font-size: 11px;")
        progress_layout.addWidget(self.progress_label)

        main_layout.addLayout(progress_layout)

        # 图标显示区域
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: #FFFFFF;
                border: 1px solid #CCCCCC;
            }
        """)

        self.icons_container = QWidget()
        self.icons_layout = QGridLayout(self.icons_container)
        self.icons_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.icons_layout.setSpacing(20)
        self.icons_layout.setContentsMargins(15, 15, 15, 15)

        self.scroll_area.setWidget(self.icons_container)
        main_layout.addWidget(self.scroll_area)

        # 状态栏
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")

    # ---------- 进度条辅助 ----------
    def update_progress(self, value, message=""):
        """更新进度条和状态"""
        self.progress_bar.setValue(value)
        if message:
            self.progress_label.setText(message)
        QApplication.processEvents()

    def hide_progress(self):
        """隐藏进度条"""
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.progress_bar.setValue(0)
        self.progress_label.setText("")

    # ---------- 拖拽事件 ----------
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if file_path.lower().endswith(('.exe', '.dll')):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if file_path.lower().endswith(('.exe', '.dll')):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if file_path.lower().endswith(('.exe', '.dll')):
                    self.process_dropped_file(file_path)
                    event.acceptProposedAction()
                    return
        event.ignore()

    def process_dropped_file(self, file_path):
        """处理拖拽或选择的文件"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "文件不存在", "拖拽的文件不存在")
            return

        self.current_file = file_path
        self.file_label.setText(os.path.basename(file_path))
        self.status_bar.showMessage(f"加载中: {os.path.basename(file_path)}...")

        # 清空当前显示的图标
        self.clear_icons()

        # 显示进度条
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_label.setText("初始化...")
        QApplication.processEvents()

        try:
            # 进度回调
            def progress_callback(value, message=""):
                self.update_progress(value, message)

            if file_path.lower().endswith(('.exe', '.dll')):
                self.current_icons = IconExtractor.extract_icons_from_exe(file_path, progress_callback)
            elif file_path.lower().endswith('.ico'):
                self.current_icons = IconExtractor.extract_icons_from_ico(file_path, progress_callback)
            else:
                QMessageBox.warning(self, "不支持的格式", "请拖拽 .exe 或 .dll 文件")
                self.hide_progress()
                return

            # 完成
            self.update_progress(100, "完成!")
            QTimer.singleShot(500, self.hide_progress)

        except Exception as e:
            QMessageBox.critical(self, "处理文件出错", f"处理文件时发生错误: {str(e)}")
            print(f"处理文件时出错: {e}")
            self.hide_progress()

        if not self.current_icons:
            self.status_bar.showMessage("未找到图标")
            self.save_all_button.setEnabled(False)  # 无图标时禁用批量导出
            QMessageBox.information(self, "无图标", "在文件中未找到图标")
            return

        self.status_bar.showMessage(f"找到 {len(self.current_icons)} 个图标")
        self.save_all_button.setEnabled(True)  # 有图标时启用批量导出

        # 排序并显示
        self.sort_and_display_icons()

    # ---------- 清除功能 ----------
    def clear_all(self):
        """清除当前加载的文件和图标，恢复初始状态"""
        self.current_icons = []
        self.current_file = ""
        self.clear_icons()  # 清空网格布局
        self.file_label.setText("未选择文件 - 可拖拽文件到窗口")
        self.save_all_button.setEnabled(False)  # 禁用批量导出
        self.hide_progress()  # 隐藏进度条
        self.status_bar.showMessage("已清除")

    # ---------- 排序 ----------
    def on_sort_changed(self, sort_type):
        if sort_type == "按尺寸":
            self.sort_by = "size"
        elif sort_type == "按宽度":
            self.sort_by = "width"
        elif sort_type == "按高度":
            self.sort_by = "height"
        elif sort_type == "按面积":
            self.sort_by = "area"

        if self.current_icons:
            self.sort_and_display_icons()

    def on_direction_changed(self, direction):
        self.sort_direction = Qt.SortOrder.AscendingOrder if direction == "升序" else Qt.SortOrder.DescendingOrder
        if self.current_icons:
            self.sort_and_display_icons()

    def sort_and_display_icons(self):
        """排序并显示图标"""
        if not self.current_icons:
            return

        icons_with_keys = []
        for pixmap, size_str in self.current_icons:
            try:
                w, h = map(int, size_str.split('x'))
                area = w * h
                if self.sort_by == "size":
                    key = size_str
                elif self.sort_by == "width":
                    key = w
                elif self.sort_by == "height":
                    key = h
                else:  # area
                    key = area
                icons_with_keys.append((key, pixmap, size_str))
            except:
                icons_with_keys.append((size_str, pixmap, size_str))

        # 修正排序方向
        reverse = (self.sort_direction == Qt.SortOrder.DescendingOrder)
        icons_with_keys.sort(key=lambda x: x[0], reverse=reverse)

        self.current_icons = [(pixmap, size_str) for _, pixmap, size_str in icons_with_keys]
        self.display_icons()

    # ---------- 主题 ----------
    def _apply_theme(self, colors):
        """根据颜色字典应用主题"""
        self.current_theme = 0 if colors['name'] == 'dark' else 1
        self.theme_button.setText(colors['button_text'])

        stylesheet = f"""
            QMainWindow, QDialog, QWidget {{
                background-color: {colors['base']};
                color: {colors['text']};
            }}
            QPushButton {{
                background-color: {colors['btn_bg']};
                color: {colors['text']};
                border: 1px solid {colors['border']};
                border-radius: 4px;
                padding: 5px;
            }}
            QPushButton:hover {{
                background-color: {colors['btn_hover']};
            }}
            QPushButton:pressed {{
                background-color: {colors['accent']};
                color: {colors['accent_text']};
            }}
            QLabel {{
                color: {colors['text']};
            }}
            QScrollArea {{
                background-color: {colors['scroll_bg']};
                border: 1px solid {colors['border']};
            }}
            QProgressBar {{
                border: 1px solid {colors['border']};
                border-radius: 4px;
                text-align: center;
                background-color: {colors['progress_bg']};
                color: {colors['text']};
            }}
            QProgressBar::chunk {{
                background-color: {colors['accent']};
                width: 10px;
            }}
            QGroupBox {{
                color: {colors['text']};
                border: 1px solid {colors['border']};
                border-radius: 5px;
                margin-top: 1ex;
                font-weight: bold;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
                background-color: {colors['base']};
            }}
            QCheckBox, QComboBox, QTextEdit {{
                color: {colors['text']};
                background-color: {colors['combo_bg']};
            }}
            QComboBox {{
                background-color: {colors['combo_bg']};
                border: 1px solid {colors['border']};
                padding: 3px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {colors['combo_item_bg']};
                color: {colors['text']};
                selection-background-color: {colors['accent']};
            }}
            QTextEdit {{
                background-color: {colors['scroll_bg']};
                border: 1px solid {colors['border']};
                border-radius: 4px;
            }}
        """
        self.setStyleSheet(stylesheet)
        self.scroll_area.setStyleSheet(
            f"QScrollArea {{ background-color: {colors['scroll_bg']}; border: 1px solid {colors['border']}; }}")

    def apply_dark_theme(self):
        self._apply_theme({
            'name': 'dark',
            'button_text': '切换浅色主题',
            'base': '#2D2D30',
            'text': '#F1F1F1',
            'accent': '#007ACC',
            'accent_text': '#F1F1F1',
            'btn_bg': '#3E3E42',
            'btn_hover': '#505054',
            'border': '#555555',
            'scroll_bg': '#252526',
            'progress_bg': '#1E1E1E',
            'combo_bg': '#3E3E42',
            'combo_item_bg': '#3E3E42',
        })

    def apply_light_theme(self):
        self._apply_theme({
            'name': 'light',
            'button_text': '切换深色主题',
            'base': '#F0F0F0',
            'text': '#333333',
            'accent': '#1E88E5',
            'accent_text': 'white',
            'btn_bg': '#F0F0F0',
            'btn_hover': '#D0D0D0',
            'border': '#CCCCCC',
            'scroll_bg': '#FFFFFF',
            'progress_bg': '#FFFFFF',
            'combo_bg': '#F0F0F0',
            'combo_item_bg': '#FFFFFF',
        })

    def toggle_theme(self):
        if self.current_theme == 0:
            self.apply_light_theme()
        else:
            self.apply_dark_theme()
        if self.current_icons:
            self.display_icons()

    # ---------- 对话框 ----------
    def show_about(self):
        about_dialog = AboutDialog(self)
        about_dialog.exec()

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择可执行文件或 DLL",
            "/",
            "可执行文件 (*.exe *.dll)")
        if not file_path:
            return
        self.process_dropped_file(file_path)

    # ---------- 图标显示 ----------
    def clear_icons(self):
        while self.icons_layout.count():
            child = self.icons_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        self.current_icons = []

    def display_icons(self):
        if not self.current_icons:
            return

        row, col = 0, 0
        max_columns = 5

        if self.current_theme == 0:
            container_style = "background-color: #252526; border-radius: 5px;"
            label_style = "color: #FFFFFF; font-size: 10px; font-weight: bold;"
            button_style = """
                QPushButton {
                    background-color: #3A3A3A;
                    border: 1px solid #555555;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #4A4A4A;
                }
                QPushButton:pressed {
                    background-color: #007ACC;
                }
            """
        else:
            container_style = "background-color: #FFFFFF; border: 1px solid #CCCCCC; border-radius: 5px;"
            label_style = "color: #000000; font-size: 10px; font-weight: bold; border: none;"
            button_style = """
                QPushButton {
                    background-color: #F0F0F0;
                    border: 1px solid #CCCCCC;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #e6e6e6;
                }
                QPushButton:pressed {
                    background-color: #1E88E5;
                }
            """

        for i, (pixmap, size_str) in enumerate(self.current_icons):
            icon_button = QPushButton()
            icon_button.setIcon(QIcon(pixmap))
            icon_button.setIconSize(QSize(64, 64))
            icon_button.setFixedSize(100, 100)
            icon_button.setToolTip(f"尺寸: {size_str}\n点击保存")
            icon_button.clicked.connect(lambda checked, idx=i: self.save_single_icon(idx))
            icon_button.setStyleSheet(button_style)

            container = QWidget()
            container.setStyleSheet(container_style)
            container_layout = QVBoxLayout(container)
            container_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            container_layout.setSpacing(5)
            container_layout.setContentsMargins(5, 5, 5, 5)

            size_label = QLabel(size_str)
            size_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            size_label.setStyleSheet(label_style)

            container_layout.addWidget(icon_button)
            container_layout.addWidget(size_label)

            self.icons_layout.addWidget(container, row, col)

            col += 1
            if col >= max_columns:
                col = 0
                row += 1

    # ---------- 导出辅助 ----------
    def _save_pixmap_as_jpg(self, pixmap, save_path):
        """将 QPixmap 保存为 JPEG（白色背景），使用 QImage 原生编码"""
        temp_pixmap = QPixmap(pixmap.size())
        temp_pixmap.fill(Qt.GlobalColor.white)
        painter = QPainter(temp_pixmap)
        painter.drawPixmap(0, 0, pixmap)
        painter.end()
        qimage = temp_pixmap.toImage().convertToFormat(QImage.Format.Format_RGB888)
        return qimage.save(save_path, "JPEG", 95)

    def _save_pixmap_as_ico(self, pixmap, save_path):
        """将 QPixmap 保存为 ICO（透明背景），使用 QImage 原生编码"""
        temp_pixmap = QPixmap(pixmap.size())
        temp_pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(temp_pixmap)
        painter.drawPixmap(0, 0, pixmap)
        painter.end()
        qimage = temp_pixmap.toImage().convertToFormat(QImage.Format.Format_ARGB32)
        return qimage.save(save_path, "ICO")

    # ---------- 保存 ----------
    def save_single_icon(self, index):
        if index < 0 or index >= len(self.current_icons):
            return

        pixmap, size_str = self.current_icons[index]
        base_name = os.path.splitext(os.path.basename(self.current_file))[0]
        default_name = f"/{base_name}_{size_str}"
        save_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "保存图标",
            default_name,
            "PNG 图片 (*.png);;JPEG 图片 (*.jpg);;ICO 图标 (*.ico)")

        if not save_path:
            return

        success = False
        if selected_filter == "PNG 图片 (*.png)":
            if not save_path.lower().endswith('.png'):
                save_path += '.png'
            success = pixmap.save(save_path, "PNG")

        elif selected_filter == "JPEG 图片 (*.jpg)":
            if not save_path.lower().endswith('.jpg'):
                save_path += '.jpg'

            reply = QMessageBox.question(
                self,
                "提示",
                "JPEG 格式不支持透明背景。是否继续保存图片？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                success = self._save_pixmap_as_jpg(pixmap, save_path)

        elif selected_filter == "ICO 图标 (*.ico)":
            if not save_path.lower().endswith('.ico'):
                save_path += '.ico'
            success = self._save_pixmap_as_ico(pixmap, save_path)

        if success:
            self.status_bar.showMessage(f"图标已保存: {os.path.basename(save_path)}")
            QMessageBox.information(self, "保存成功", f"图标已保存为:\n{os.path.basename(save_path)}")
        else:
            QMessageBox.warning(self, "保存失败", "请重新保存")

    def save_all_icons(self):
        if not self.current_icons:
            return

        dialog = ExportOptionsDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        export_options = dialog.get_export_options()
        if not any(export_options.values()):
            QMessageBox.warning(self, "警告", "请至少选择一种导出格式")
            return

        save_dir = QFileDialog.getExistingDirectory(self, "选择保存目录", "/")
        if not save_dir:
            return

        base_name = os.path.splitext(os.path.basename(self.current_file))[0]

        # 创建各格式目录
        if export_options['export_png']:
            png_dir = os.path.join(save_dir, f"{base_name}_PNG")
            os.makedirs(png_dir, exist_ok=True)
        if export_options['export_jpg']:
            jpg_dir = os.path.join(save_dir, f"{base_name}_JPG")
            os.makedirs(jpg_dir, exist_ok=True)
        if export_options['export_ico']:
            ico_dir = os.path.join(save_dir, f"{base_name}_ICO")
            os.makedirs(ico_dir, exist_ok=True)

        # 显示进度条
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.progress_bar.setRange(0, len(self.current_icons))
        self.progress_bar.setValue(0)
        self.progress_label.setText("准备导出...")
        QApplication.processEvents()

        saved_counts = {'PNG': 0, 'JPG': 0, 'ICO': 0}

        for i, (pixmap, size_str) in enumerate(self.current_icons):
            self.progress_bar.setValue(i)
            self.progress_label.setText(f"导出图标 {i+1}/{len(self.current_icons)}")
            QApplication.processEvents()

            # PNG
            if export_options['export_png']:
                save_path = os.path.join(png_dir, f"{base_name}_{i+1}_{size_str}.png")
                try:
                    if pixmap.save(save_path, "PNG"):
                        saved_counts['PNG'] += 1
                except Exception as e:
                    print(f"保存 PNG 图标 {i} 时出错: {e}")

            # JPG
            if export_options['export_jpg']:
                save_path = os.path.join(jpg_dir, f"{base_name}_{i+1}_{size_str}.jpg")
                try:
                    if self._save_pixmap_as_jpg(pixmap, save_path):
                        saved_counts['JPG'] += 1
                except Exception as e:
                    print(f"保存 JPG 图标 {i} 时出错: {e}")

            # ICO
            if export_options['export_ico']:
                save_path = os.path.join(ico_dir, f"{base_name}_{i+1}_{size_str}.ico")
                try:
                    if self._save_pixmap_as_ico(pixmap, save_path):
                        saved_counts['ICO'] += 1
                except Exception as e:
                    print(f"保存 ICO 图标 {i} 时出错: {e}")

        self.progress_bar.setValue(len(self.current_icons))
        self.progress_label.setText("导出完成!")
        QApplication.processEvents()
        QTimer.singleShot(960, self.hide_progress)

        result_msg = "批量导出完成:\n"
        if saved_counts['PNG']:
            result_msg += f"PNG: {saved_counts['PNG']} 个图标\n"
        if saved_counts['JPG']:
            result_msg += f"JPG: {saved_counts['JPG']} 个图标\n"
        if saved_counts['ICO']:
            result_msg += f"ICO: {saved_counts['ICO']} 个图标\n"
        result_msg += f"保存位置: {save_dir}"

        self.status_bar.showMessage(f"批量导出完成: {save_dir}")
        QMessageBox.information(self, "导出完成", result_msg)


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.environ['QT_QPA_PLATFORM'] = 'xcb' 
    app = QApplication(sys.argv)
    translator = QTranslator()
    translator.load(os.path.join(_SCRIPT_DIR, 'chs.qm'))
    app.installTranslator(translator)
    window = IconExtractorApp()
    window.show()
    sys.exit(app.exec())
