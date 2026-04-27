package im.uwrkaxlmjj.ui.cells;

import android.animation.ArgbEvaluator;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.SystemClock;
import android.text.TextPaint;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ThemeSetUrlActivity;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackgroundGradientDrawable;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadioButton;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ThemesHorizontalListCell extends RecyclerListView implements NotificationCenter.NotificationCenterDelegate {
    private static byte[] bytes = new byte[1024];
    private ThemesListAdapter adapter;
    private int currentType;
    private ArrayList<Theme.ThemeInfo> darkThemes;
    private ArrayList<Theme.ThemeInfo> defaultThemes;
    private boolean drawDivider;
    private LinearLayoutManager horizontalLayoutManager;
    private HashMap<String, Theme.ThemeInfo> loadingThemes;
    private HashMap<Theme.ThemeInfo, String> loadingWallpapers;
    private Theme.ThemeInfo prevThemeInfo;

    private class ThemesListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        ThemesListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            return new RecyclerListView.Holder(ThemesHorizontalListCell.this.new InnerThemeView(this.mContext));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            ArrayList<Theme.ThemeInfo> arrayList;
            InnerThemeView view = (InnerThemeView) holder.itemView;
            int p = position;
            if (position < ThemesHorizontalListCell.this.defaultThemes.size()) {
                arrayList = ThemesHorizontalListCell.this.defaultThemes;
            } else {
                arrayList = ThemesHorizontalListCell.this.darkThemes;
                p -= ThemesHorizontalListCell.this.defaultThemes.size();
            }
            view.setTheme(arrayList.get(p), position == getItemCount() - 1, position == 0);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return ThemesHorizontalListCell.this.defaultThemes.size() + ThemesHorizontalListCell.this.darkThemes.size();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class InnerThemeView extends FrameLayout {
        private ObjectAnimator accentAnimator;
        private int accentColor;
        private boolean accentColorChanged;
        private float accentState;
        private Drawable backgroundDrawable;
        private Paint bitmapPaint;
        private BitmapShader bitmapShader;
        private RadioButton button;
        private final ArgbEvaluator evaluator;
        private boolean hasWhiteBackground;
        private Drawable inDrawable;
        private boolean isFirst;
        private boolean isLast;
        private long lastDrawTime;
        private int loadingColor;
        private Drawable loadingDrawable;
        private int oldAccentColor;
        private Drawable optionsDrawable;
        private Drawable outDrawable;
        private Paint paint;
        private float placeholderAlpha;
        private boolean pressed;
        private RectF rect;
        private Matrix shaderMatrix;
        private TextPaint textPaint;
        private Theme.ThemeInfo themeInfo;

        public InnerThemeView(Context context) {
            super(context);
            this.rect = new RectF();
            this.paint = new Paint(1);
            this.textPaint = new TextPaint(1);
            this.evaluator = new ArgbEvaluator();
            this.bitmapPaint = new Paint(3);
            this.shaderMatrix = new Matrix();
            setWillNotDraw(false);
            this.inDrawable = context.getResources().getDrawable(R.drawable.minibubble_in).mutate();
            this.outDrawable = context.getResources().getDrawable(R.drawable.minibubble_out).mutate();
            this.textPaint.setTextSize(AndroidUtilities.dp(13.0f));
            RadioButton radioButton = new RadioButton(context) { // from class: im.uwrkaxlmjj.ui.cells.ThemesHorizontalListCell.InnerThemeView.1
                @Override // android.view.View
                public void invalidate() {
                    super.invalidate();
                }
            };
            this.button = radioButton;
            radioButton.setSize(AndroidUtilities.dp(20.0f));
            addView(this.button, LayoutHelper.createFrame(22.0f, 22.0f, 51, 27.0f, 75.0f, 0.0f, 0.0f));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp((this.isLast ? 22 : 15) + 76 + (this.isFirst ? 22 : 0)), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(148.0f), 1073741824));
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            Theme.ThemeInfo themeInfo;
            if (this.optionsDrawable == null || (themeInfo = this.themeInfo) == null || ((themeInfo.info != null && !this.themeInfo.themeLoaded) || ThemesHorizontalListCell.this.currentType != 0)) {
                return super.onTouchEvent(event);
            }
            int action = event.getAction();
            if (action == 0 || action == 1) {
                float x = event.getX();
                float y = event.getY();
                if (x > this.rect.centerX() && y < this.rect.centerY() - AndroidUtilities.dp(10.0f)) {
                    if (action == 0) {
                        this.pressed = true;
                    } else {
                        performHapticFeedback(3);
                        ThemesHorizontalListCell.this.showOptionsForTheme(this.themeInfo);
                    }
                }
                if (action == 1) {
                    this.pressed = false;
                }
            }
            return this.pressed;
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        /* JADX WARN: Removed duplicated region for block: B:133:0x0262  */
        /* JADX WARN: Removed duplicated region for block: B:63:0x0161  */
        /* JADX WARN: Removed duplicated region for block: B:64:0x0162 A[Catch: all -> 0x01ab, TryCatch #5 {all -> 0x01ab, blocks: (B:17:0x006f, B:19:0x009d, B:21:0x00aa, B:24:0x00ae, B:26:0x00b1, B:28:0x00bb, B:29:0x00c0, B:33:0x00cf, B:35:0x00df, B:36:0x00eb, B:38:0x00f5, B:41:0x0107, B:43:0x010d, B:45:0x0113, B:49:0x011e, B:51:0x012c, B:54:0x0139, B:61:0x0157, B:62:0x015e, B:84:0x018e, B:85:0x0193, B:86:0x0198, B:87:0x019d, B:64:0x0162, B:67:0x016a, B:70:0x0172, B:73:0x017a, B:60:0x014f, B:58:0x0141), top: B:146:0x006f, inners: #1 }] */
        /* JADX WARN: Removed duplicated region for block: B:67:0x016a A[Catch: all -> 0x01ab, TryCatch #5 {all -> 0x01ab, blocks: (B:17:0x006f, B:19:0x009d, B:21:0x00aa, B:24:0x00ae, B:26:0x00b1, B:28:0x00bb, B:29:0x00c0, B:33:0x00cf, B:35:0x00df, B:36:0x00eb, B:38:0x00f5, B:41:0x0107, B:43:0x010d, B:45:0x0113, B:49:0x011e, B:51:0x012c, B:54:0x0139, B:61:0x0157, B:62:0x015e, B:84:0x018e, B:85:0x0193, B:86:0x0198, B:87:0x019d, B:64:0x0162, B:67:0x016a, B:70:0x0172, B:73:0x017a, B:60:0x014f, B:58:0x0141), top: B:146:0x006f, inners: #1 }] */
        /* JADX WARN: Removed duplicated region for block: B:70:0x0172 A[Catch: all -> 0x01ab, TryCatch #5 {all -> 0x01ab, blocks: (B:17:0x006f, B:19:0x009d, B:21:0x00aa, B:24:0x00ae, B:26:0x00b1, B:28:0x00bb, B:29:0x00c0, B:33:0x00cf, B:35:0x00df, B:36:0x00eb, B:38:0x00f5, B:41:0x0107, B:43:0x010d, B:45:0x0113, B:49:0x011e, B:51:0x012c, B:54:0x0139, B:61:0x0157, B:62:0x015e, B:84:0x018e, B:85:0x0193, B:86:0x0198, B:87:0x019d, B:64:0x0162, B:67:0x016a, B:70:0x0172, B:73:0x017a, B:60:0x014f, B:58:0x0141), top: B:146:0x006f, inners: #1 }] */
        /* JADX WARN: Removed duplicated region for block: B:73:0x017a A[Catch: all -> 0x01ab, TryCatch #5 {all -> 0x01ab, blocks: (B:17:0x006f, B:19:0x009d, B:21:0x00aa, B:24:0x00ae, B:26:0x00b1, B:28:0x00bb, B:29:0x00c0, B:33:0x00cf, B:35:0x00df, B:36:0x00eb, B:38:0x00f5, B:41:0x0107, B:43:0x010d, B:45:0x0113, B:49:0x011e, B:51:0x012c, B:54:0x0139, B:61:0x0157, B:62:0x015e, B:84:0x018e, B:85:0x0193, B:86:0x0198, B:87:0x019d, B:64:0x0162, B:67:0x016a, B:70:0x0172, B:73:0x017a, B:60:0x014f, B:58:0x0141), top: B:146:0x006f, inners: #1 }] */
        /* JADX WARN: Removed duplicated region for block: B:78:0x0185  */
        /* JADX WARN: Removed duplicated region for block: B:87:0x019d A[Catch: all -> 0x01ab, TRY_LEAVE, TryCatch #5 {all -> 0x01ab, blocks: (B:17:0x006f, B:19:0x009d, B:21:0x00aa, B:24:0x00ae, B:26:0x00b1, B:28:0x00bb, B:29:0x00c0, B:33:0x00cf, B:35:0x00df, B:36:0x00eb, B:38:0x00f5, B:41:0x0107, B:43:0x010d, B:45:0x0113, B:49:0x011e, B:51:0x012c, B:54:0x0139, B:61:0x0157, B:62:0x015e, B:84:0x018e, B:85:0x0193, B:86:0x0198, B:87:0x019d, B:64:0x0162, B:67:0x016a, B:70:0x0172, B:73:0x017a, B:60:0x014f, B:58:0x0141), top: B:146:0x006f, inners: #1 }] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean parseTheme() {
            /*
                Method dump skipped, instruction units count: 636
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ThemesHorizontalListCell.InnerThemeView.parseTheme():boolean");
        }

        public /* synthetic */ void lambda$parseTheme$1$ThemesHorizontalListCell$InnerThemeView(final TLObject response, TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ThemesHorizontalListCell$InnerThemeView$fY9nPihk_6rjIxGarXq2MzqRf2E
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$ThemesHorizontalListCell$InnerThemeView(response);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$ThemesHorizontalListCell$InnerThemeView(TLObject response) {
            if (response instanceof TLRPC.TL_wallPaper) {
                TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) response;
                String name = FileLoader.getAttachFileName(wallPaper.document);
                if (!ThemesHorizontalListCell.this.loadingThemes.containsKey(name)) {
                    ThemesHorizontalListCell.this.loadingThemes.put(name, this.themeInfo);
                    FileLoader.getInstance(this.themeInfo.account).loadFile(wallPaper.document, wallPaper, 1, 1);
                    return;
                }
                return;
            }
            this.themeInfo.badWallpaper = true;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void applyTheme() {
            this.inDrawable.setColorFilter(new PorterDuffColorFilter(this.themeInfo.previewInColor, PorterDuff.Mode.MULTIPLY));
            this.outDrawable.setColorFilter(new PorterDuffColorFilter(this.themeInfo.previewOutColor, PorterDuff.Mode.MULTIPLY));
            if (this.themeInfo.pathToFile == null) {
                updateAccentColor(this.themeInfo.accentColor, false);
                this.optionsDrawable = null;
            } else {
                this.optionsDrawable = getResources().getDrawable(R.drawable.preview_dots).mutate();
            }
            this.bitmapShader = null;
            this.backgroundDrawable = null;
            double[] hsv = null;
            if (this.themeInfo.previewBackgroundGradientColor != 0) {
                BackgroundGradientDrawable drawable = new BackgroundGradientDrawable(GradientDrawable.Orientation.BL_TR, new int[]{this.themeInfo.previewBackgroundColor, this.themeInfo.previewBackgroundGradientColor});
                drawable.setCornerRadius(AndroidUtilities.dp(6.0f));
                this.backgroundDrawable = drawable;
                hsv = AndroidUtilities.rgbToHsv(Color.red(this.themeInfo.previewBackgroundColor), Color.green(this.themeInfo.previewBackgroundColor), Color.blue(this.themeInfo.previewBackgroundColor));
            } else if (this.themeInfo.previewWallpaperOffset > 0 || this.themeInfo.pathToWallpaper != null) {
                Bitmap wallpaper = ThemesHorizontalListCell.getScaledBitmap(AndroidUtilities.dp(76.0f), AndroidUtilities.dp(97.0f), this.themeInfo.pathToWallpaper, this.themeInfo.pathToFile, this.themeInfo.previewWallpaperOffset);
                if (wallpaper != null) {
                    this.backgroundDrawable = new BitmapDrawable(wallpaper);
                    BitmapShader bitmapShader = new BitmapShader(wallpaper, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
                    this.bitmapShader = bitmapShader;
                    this.bitmapPaint.setShader(bitmapShader);
                    int[] colors = AndroidUtilities.calcDrawableColor(this.backgroundDrawable);
                    hsv = AndroidUtilities.rgbToHsv(Color.red(colors[0]), Color.green(colors[0]), Color.blue(colors[0]));
                }
            } else if (this.themeInfo.previewBackgroundColor != 0) {
                hsv = AndroidUtilities.rgbToHsv(Color.red(this.themeInfo.previewBackgroundColor), Color.green(this.themeInfo.previewBackgroundColor), Color.blue(this.themeInfo.previewBackgroundColor));
            }
            if (hsv != null && hsv[1] <= 0.10000000149011612d && hsv[2] >= 0.9599999785423279d) {
                this.hasWhiteBackground = true;
            } else {
                this.hasWhiteBackground = false;
            }
            if (this.themeInfo.previewBackgroundColor == 0 && this.themeInfo.previewParsed && this.backgroundDrawable == null) {
                BitmapDrawable drawable2 = (BitmapDrawable) getResources().getDrawable(R.drawable.catstile).mutate();
                BitmapShader bitmapShader2 = new BitmapShader(drawable2.getBitmap(), Shader.TileMode.REPEAT, Shader.TileMode.REPEAT);
                this.bitmapShader = bitmapShader2;
                this.bitmapPaint.setShader(bitmapShader2);
                this.backgroundDrawable = drawable2;
            }
            invalidate();
        }

        public void setTheme(Theme.ThemeInfo theme, boolean last, boolean first) {
            this.themeInfo = theme;
            this.isFirst = first;
            this.isLast = last;
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.button.getLayoutParams();
            layoutParams.leftMargin = AndroidUtilities.dp(this.isFirst ? 49.0f : 27.0f);
            this.button.setLayoutParams(layoutParams);
            this.placeholderAlpha = 0.0f;
            if (this.themeInfo.pathToFile != null && !this.themeInfo.previewParsed) {
                this.themeInfo.previewInColor = Theme.getDefaultColor(Theme.key_chat_inBubble);
                this.themeInfo.previewOutColor = Theme.getDefaultColor(Theme.key_chat_outBubble);
                File file = new File(this.themeInfo.pathToFile);
                boolean fileExists = file.exists();
                boolean parsed = fileExists && parseTheme();
                if ((!parsed || !fileExists) && this.themeInfo.info != null) {
                    if (this.themeInfo.info.document != null) {
                        this.themeInfo.themeLoaded = false;
                        this.placeholderAlpha = 1.0f;
                        Drawable drawableMutate = getResources().getDrawable(R.drawable.msg_theme).mutate();
                        this.loadingDrawable = drawableMutate;
                        int color = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7);
                        this.loadingColor = color;
                        Theme.setDrawableColor(drawableMutate, color);
                        if (!fileExists) {
                            String name = FileLoader.getAttachFileName(this.themeInfo.info.document);
                            if (!ThemesHorizontalListCell.this.loadingThemes.containsKey(name)) {
                                ThemesHorizontalListCell.this.loadingThemes.put(name, this.themeInfo);
                                FileLoader.getInstance(this.themeInfo.account).loadFile(this.themeInfo.info.document, this.themeInfo.info, 1, 1);
                            }
                        }
                    } else {
                        Drawable drawableMutate2 = getResources().getDrawable(R.drawable.preview_custom).mutate();
                        this.loadingDrawable = drawableMutate2;
                        int color2 = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7);
                        this.loadingColor = color2;
                        Theme.setDrawableColor(drawableMutate2, color2);
                    }
                }
            }
            applyTheme();
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            Theme.ThemeInfo t = ThemesHorizontalListCell.this.currentType == 1 ? Theme.getCurrentNightTheme() : Theme.getCurrentTheme();
            this.button.setChecked(this.themeInfo == t, false);
            Theme.ThemeInfo themeInfo = this.themeInfo;
            if (themeInfo != null && themeInfo.info != null && !this.themeInfo.themeLoaded) {
                String name = FileLoader.getAttachFileName(this.themeInfo.info.document);
                if (!ThemesHorizontalListCell.this.loadingThemes.containsKey(name) && !ThemesHorizontalListCell.this.loadingWallpapers.containsKey(this.themeInfo)) {
                    this.themeInfo.themeLoaded = true;
                    this.placeholderAlpha = 0.0f;
                    parseTheme();
                    applyTheme();
                }
            }
        }

        public void updateCurrentThemeCheck() {
            Theme.ThemeInfo t = ThemesHorizontalListCell.this.currentType == 1 ? Theme.getCurrentNightTheme() : Theme.getCurrentTheme();
            this.button.setChecked(this.themeInfo == t, true);
        }

        void updateAccentColor(int accent, boolean animate) {
            this.oldAccentColor = this.accentColor;
            this.accentColor = accent;
            ObjectAnimator objectAnimator = this.accentAnimator;
            if (objectAnimator != null) {
                objectAnimator.cancel();
            }
            if (animate) {
                ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, "accentState", 0.0f, 1.0f);
                this.accentAnimator = objectAnimatorOfFloat;
                objectAnimatorOfFloat.setDuration(200L);
                this.accentAnimator.start();
                return;
            }
            setAccentState(1.0f);
        }

        public float getAccentState() {
            return this.accentColor;
        }

        public void setAccentState(float state) {
            this.accentState = state;
            this.accentColorChanged = true;
            invalidate();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            float f;
            float bitmapW;
            boolean drawContent = true;
            if (this.accentColor != this.themeInfo.accentColor) {
                updateAccentColor(this.themeInfo.accentColor, true);
            }
            int x = this.isFirst ? AndroidUtilities.dp(22.0f) : 0;
            int y = AndroidUtilities.dp(11.0f);
            this.rect.set(x, y, AndroidUtilities.dp(76.0f) + x, AndroidUtilities.dp(97.0f) + y);
            String name = this.themeInfo.getName();
            if (name.toLowerCase().endsWith(".attheme")) {
                name = name.substring(0, name.lastIndexOf(46));
            }
            int maxWidth = (getMeasuredWidth() - AndroidUtilities.dp(this.isFirst ? 10.0f : 15.0f)) - (this.isLast ? AndroidUtilities.dp(7.0f) : 0);
            String text = TextUtils.ellipsize(name, this.textPaint, maxWidth, TextUtils.TruncateAt.END).toString();
            int width = (int) Math.ceil(this.textPaint.measureText(text));
            this.textPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            canvas.drawText(text, ((AndroidUtilities.dp(76.0f) - width) / 2) + x, AndroidUtilities.dp(131.0f), this.textPaint);
            if (this.themeInfo.info != null && (this.themeInfo.info.document == null || !this.themeInfo.themeLoaded)) {
                drawContent = false;
            }
            if (drawContent) {
                this.paint.setColor(tint(this.themeInfo.previewBackgroundColor));
                if (this.accentColorChanged) {
                    this.inDrawable.setColorFilter(new PorterDuffColorFilter(tint(this.themeInfo.previewInColor), PorterDuff.Mode.MULTIPLY));
                    this.outDrawable.setColorFilter(new PorterDuffColorFilter(tint(this.themeInfo.previewOutColor), PorterDuff.Mode.MULTIPLY));
                    this.accentColorChanged = false;
                }
                Drawable drawable = this.backgroundDrawable;
                if (drawable == null) {
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), this.paint);
                } else if (this.bitmapShader == null) {
                    drawable.setBounds((int) this.rect.left, (int) this.rect.top, (int) this.rect.right, (int) this.rect.bottom);
                    this.backgroundDrawable.draw(canvas);
                } else {
                    BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
                    float bitmapW2 = bitmapDrawable.getBitmap().getWidth();
                    float bitmapH = bitmapDrawable.getBitmap().getHeight();
                    float scaleW = bitmapW2 / this.rect.width();
                    float scaleH = bitmapH / this.rect.height();
                    this.shaderMatrix.reset();
                    float scale = 1.0f / Math.min(scaleW, scaleH);
                    if (bitmapW2 / scaleH <= this.rect.width()) {
                        this.shaderMatrix.setTranslate(x, y - (((bitmapH / scaleW) - this.rect.height()) / 2.0f));
                        bitmapW = bitmapW2;
                    } else {
                        bitmapW = bitmapW2 / scaleH;
                        this.shaderMatrix.setTranslate(x - ((bitmapW - this.rect.width()) / 2.0f), y);
                    }
                    this.shaderMatrix.preScale(scale, scale);
                    this.bitmapShader.setLocalMatrix(this.shaderMatrix);
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), this.bitmapPaint);
                }
                this.button.setColor(1728053247, -1);
                if (this.themeInfo.accentBaseColor != 0) {
                    if ("Arctic Blue".equals(this.themeInfo.name)) {
                        this.button.setColor(-5000269, tint(this.themeInfo.accentBaseColor));
                        Theme.chat_instantViewRectPaint.setColor(733001146);
                        canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), Theme.chat_instantViewRectPaint);
                        f = 6.0f;
                    } else {
                        f = 6.0f;
                    }
                } else if (this.hasWhiteBackground) {
                    this.button.setColor(-5000269, this.themeInfo.previewOutColor);
                    Theme.chat_instantViewRectPaint.setColor(733001146);
                    f = 6.0f;
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), Theme.chat_instantViewRectPaint);
                } else {
                    f = 6.0f;
                }
                this.inDrawable.setBounds(AndroidUtilities.dp(f) + x, AndroidUtilities.dp(22.0f), AndroidUtilities.dp(49.0f) + x, AndroidUtilities.dp(36.0f));
                this.inDrawable.draw(canvas);
                this.outDrawable.setBounds(AndroidUtilities.dp(27.0f) + x, AndroidUtilities.dp(41.0f), AndroidUtilities.dp(70.0f) + x, AndroidUtilities.dp(55.0f));
                this.outDrawable.draw(canvas);
                if (this.optionsDrawable != null && ThemesHorizontalListCell.this.currentType == 0) {
                    int x2 = ((int) this.rect.right) - AndroidUtilities.dp(16.0f);
                    int y2 = ((int) this.rect.top) + AndroidUtilities.dp(6.0f);
                    Drawable drawable2 = this.optionsDrawable;
                    drawable2.setBounds(x2, y2, drawable2.getIntrinsicWidth() + x2, this.optionsDrawable.getIntrinsicHeight() + y2);
                    this.optionsDrawable.draw(canvas);
                }
            }
            if (this.themeInfo.info != null && this.themeInfo.info.document == null) {
                this.button.setAlpha(0.0f);
                Theme.chat_instantViewRectPaint.setColor(733001146);
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), Theme.chat_instantViewRectPaint);
                if (this.loadingDrawable != null) {
                    int newColor = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7);
                    if (this.loadingColor != newColor) {
                        Drawable drawable3 = this.loadingDrawable;
                        this.loadingColor = newColor;
                        Theme.setDrawableColor(drawable3, newColor);
                    }
                    int x3 = (int) (this.rect.centerX() - (this.loadingDrawable.getIntrinsicWidth() / 2));
                    int y3 = (int) (this.rect.centerY() - (this.loadingDrawable.getIntrinsicHeight() / 2));
                    Drawable drawable4 = this.loadingDrawable;
                    drawable4.setBounds(x3, y3, drawable4.getIntrinsicWidth() + x3, this.loadingDrawable.getIntrinsicHeight() + y3);
                    this.loadingDrawable.draw(canvas);
                    return;
                }
                return;
            }
            if ((this.themeInfo.info == null || this.themeInfo.themeLoaded) && this.placeholderAlpha <= 0.0f) {
                if (this.button.getAlpha() != 1.0f) {
                    this.button.setAlpha(1.0f);
                    return;
                }
                return;
            }
            this.button.setAlpha(1.0f - this.placeholderAlpha);
            this.paint.setColor(Theme.getColor(Theme.key_windowBackgroundGray));
            this.paint.setAlpha((int) (this.placeholderAlpha * 255.0f));
            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), this.paint);
            if (this.loadingDrawable != null) {
                int newColor2 = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7);
                if (this.loadingColor != newColor2) {
                    Drawable drawable5 = this.loadingDrawable;
                    this.loadingColor = newColor2;
                    Theme.setDrawableColor(drawable5, newColor2);
                }
                int x4 = (int) (this.rect.centerX() - (this.loadingDrawable.getIntrinsicWidth() / 2));
                int y4 = (int) (this.rect.centerY() - (this.loadingDrawable.getIntrinsicHeight() / 2));
                this.loadingDrawable.setAlpha((int) (this.placeholderAlpha * 255.0f));
                Drawable drawable6 = this.loadingDrawable;
                drawable6.setBounds(x4, y4, drawable6.getIntrinsicWidth() + x4, this.loadingDrawable.getIntrinsicHeight() + y4);
                this.loadingDrawable.draw(canvas);
            }
            if (this.themeInfo.themeLoaded) {
                long newTime = SystemClock.uptimeMillis();
                long dt = Math.min(17L, newTime - this.lastDrawTime);
                this.lastDrawTime = newTime;
                float f2 = this.placeholderAlpha - (dt / 180.0f);
                this.placeholderAlpha = f2;
                if (f2 < 0.0f) {
                    this.placeholderAlpha = 0.0f;
                }
                invalidate();
            }
        }

        private int tint(int color) {
            if (this.accentState == 1.0f) {
                return Theme.changeColorAccent(this.themeInfo, this.accentColor, color);
            }
            int oldColor = Theme.changeColorAccent(this.themeInfo, this.oldAccentColor, color);
            int newColor = Theme.changeColorAccent(this.themeInfo, this.accentColor, color);
            return ((Integer) this.evaluator.evaluate(this.accentState, Integer.valueOf(oldColor), Integer.valueOf(newColor))).intValue();
        }
    }

    public ThemesHorizontalListCell(Context context, int type, ArrayList<Theme.ThemeInfo> def, ArrayList<Theme.ThemeInfo> dark) {
        super(context);
        this.loadingThemes = new HashMap<>();
        this.loadingWallpapers = new HashMap<>();
        this.darkThemes = dark;
        this.defaultThemes = def;
        this.currentType = type;
        if (type == 2) {
            setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        } else {
            setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        }
        setItemAnimator(null);
        setLayoutAnimation(null);
        this.horizontalLayoutManager = new LinearLayoutManager(context) { // from class: im.uwrkaxlmjj.ui.cells.ThemesHorizontalListCell.1
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        setPadding(0, 0, 0, 0);
        setClipToPadding(false);
        this.horizontalLayoutManager.setOrientation(0);
        setLayoutManager(this.horizontalLayoutManager);
        ThemesListAdapter themesListAdapter = new ThemesListAdapter(context);
        this.adapter = themesListAdapter;
        setAdapter(themesListAdapter);
        setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ThemesHorizontalListCell$QN6o9vX6qlohA2FCJ-E6e1gQ6Zg
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$new$0$ThemesHorizontalListCell(view, i);
            }
        });
        setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ThemesHorizontalListCell$JAHQBvVbS9HLptte5iWkJdItrPg
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i) {
                return this.f$0.lambda$new$1$ThemesHorizontalListCell(view, i);
            }
        });
    }

    public /* synthetic */ void lambda$new$0$ThemesHorizontalListCell(View view1, int position) {
        InnerThemeView innerThemeView = (InnerThemeView) view1;
        Theme.ThemeInfo themeInfo = innerThemeView.themeInfo;
        if (themeInfo.info != null) {
            if (!themeInfo.themeLoaded) {
                return;
            }
            if (themeInfo.info.document == null) {
                presentFragment(new ThemeSetUrlActivity(themeInfo, true));
                return;
            }
        }
        if (this.currentType == 1) {
            if (themeInfo == Theme.getCurrentNightTheme()) {
                return;
            } else {
                Theme.setCurrentNightTheme(themeInfo);
            }
        } else if (themeInfo == Theme.getCurrentTheme()) {
            return;
        } else {
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.needSetDayNightTheme, themeInfo, false);
        }
        updateRows();
        int left = view1.getLeft();
        int right = view1.getRight();
        if (left < 0) {
            smoothScrollBy(left - AndroidUtilities.dp(8.0f), 0);
        } else if (right > getMeasuredWidth()) {
            smoothScrollBy(right - getMeasuredWidth(), 0);
        }
        int count = getChildCount();
        for (int a = 0; a < count; a++) {
            View child = getChildAt(a);
            if (child instanceof InnerThemeView) {
                ((InnerThemeView) child).updateCurrentThemeCheck();
            }
        }
    }

    public /* synthetic */ boolean lambda$new$1$ThemesHorizontalListCell(View view12, int position) {
        InnerThemeView innerThemeView = (InnerThemeView) view12;
        showOptionsForTheme(innerThemeView.themeInfo);
        return true;
    }

    public void setDrawDivider(boolean draw) {
        this.drawDivider = draw;
    }

    public void notifyDataSetChanged(int width) {
        this.adapter.notifyDataSetChanged();
        Theme.ThemeInfo t = this.currentType == 1 ? Theme.getCurrentNightTheme() : Theme.getCurrentTheme();
        if (this.prevThemeInfo != t) {
            scrollToCurrentTheme(width, false);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent e) {
        if (getParent() != null && getParent().getParent() != null) {
            getParent().getParent().requestDisallowInterceptTouchEvent(true);
        }
        return super.onInterceptTouchEvent(e);
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (this.drawDivider) {
            canvas.drawLine(LocaleController.isRTL ? 0.0f : AndroidUtilities.dp(20.0f), getMeasuredHeight() - 1, getMeasuredWidth() - (LocaleController.isRTL ? AndroidUtilities.dp(20.0f) : 0), getMeasuredHeight() - 1, Theme.dividerPaint);
        }
    }

    public static Bitmap getScaledBitmap(float w, float h, String path, String streamPath, int streamOffset) {
        BitmapFactory.Options options;
        Bitmap wallpaper;
        FileInputStream stream = null;
        try {
            try {
                options = new BitmapFactory.Options();
                options.inJustDecodeBounds = true;
                if (path != null) {
                    BitmapFactory.decodeFile(path, options);
                } else {
                    stream = new FileInputStream(streamPath);
                    stream.getChannel().position(streamOffset);
                    BitmapFactory.decodeStream(stream, null, options);
                }
            } catch (Throwable e) {
                try {
                    FileLog.e(e);
                    if (0 != 0) {
                        stream.close();
                    }
                } finally {
                    if (0 != 0) {
                        try {
                            stream.close();
                        } catch (Exception e2) {
                            FileLog.e(e2);
                        }
                    }
                }
            }
        } catch (Exception e22) {
            FileLog.e(e22);
        }
        if (options.outWidth <= 0 || options.outHeight <= 0) {
            if (stream != null) {
                stream.close();
            }
            return null;
        }
        if (w > h && options.outWidth < options.outHeight) {
            w = h;
            h = w;
        }
        float scale = Math.min(options.outWidth / w, options.outHeight / h);
        options.inSampleSize = 1;
        if (scale > 1.0f) {
            do {
                options.inSampleSize *= 2;
            } while (options.inSampleSize < scale);
        }
        options.inJustDecodeBounds = false;
        if (path != null) {
            wallpaper = BitmapFactory.decodeFile(path, options);
        } else {
            stream.getChannel().position(streamOffset);
            wallpaper = BitmapFactory.decodeStream(stream, null, options);
        }
        return wallpaper;
    }

    @Override // android.view.View
    public void setBackgroundColor(int color) {
        super.setBackgroundColor(color);
        invalidateViews();
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        for (int a = 0; a < 3; a++) {
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.fileDidLoad);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.fileDidFailToLoad);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        for (int a = 0; a < 3; a++) {
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.fileDidLoad);
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.fileDidFailToLoad);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.fileDidLoad) {
            String fileName = (String) args[0];
            final File file = (File) args[1];
            final Theme.ThemeInfo info = this.loadingThemes.get(fileName);
            if (info != null) {
                this.loadingThemes.remove(fileName);
                if (this.loadingWallpapers.remove(info) != null) {
                    Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ThemesHorizontalListCell$w0s_r_aRxmwLdMrwx1ZTq9o0rr8
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$didReceivedNotification$3$ThemesHorizontalListCell(file, info);
                        }
                    });
                    return;
                } else {
                    lambda$null$2$ThemesHorizontalListCell(info);
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.fileDidFailToLoad) {
            this.loadingThemes.remove((String) args[0]);
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$3$ThemesHorizontalListCell(File file, final Theme.ThemeInfo info) {
        try {
            Bitmap bitmap = getScaledBitmap(AndroidUtilities.dp(640.0f), AndroidUtilities.dp(360.0f), file.getAbsolutePath(), null, 0);
            if (info.isBlured) {
                bitmap = Utilities.blurWallpaper(bitmap);
            }
            FileOutputStream stream = new FileOutputStream(info.pathToWallpaper);
            bitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream);
            stream.close();
        } catch (Throwable e) {
            FileLog.e(e);
            info.badWallpaper = true;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ThemesHorizontalListCell$6eDbikNC-b_NhKq_5wPWIgDLWzE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$ThemesHorizontalListCell(info);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: checkVisibleTheme, reason: merged with bridge method [inline-methods] */
    public void lambda$null$2$ThemesHorizontalListCell(Theme.ThemeInfo info) {
        int count = getChildCount();
        for (int a = 0; a < count; a++) {
            View child = getChildAt(a);
            if (child instanceof InnerThemeView) {
                InnerThemeView view = (InnerThemeView) child;
                if (view.themeInfo == info && view.parseTheme()) {
                    view.themeInfo.themeLoaded = true;
                    view.applyTheme();
                }
            }
        }
    }

    public void scrollToCurrentTheme(int width, boolean animated) {
        View parent;
        if (width == 0 && (parent = (View) getParent()) != null) {
            width = parent.getMeasuredWidth();
        }
        if (width == 0) {
            return;
        }
        Theme.ThemeInfo currentNightTheme = this.currentType == 1 ? Theme.getCurrentNightTheme() : Theme.getCurrentTheme();
        this.prevThemeInfo = currentNightTheme;
        int index = this.defaultThemes.indexOf(currentNightTheme);
        if (index < 0 && (index = this.darkThemes.indexOf(this.prevThemeInfo) + this.defaultThemes.size()) < 0) {
            return;
        }
        if (animated) {
            smoothScrollToPosition(index);
        } else {
            this.horizontalLayoutManager.scrollToPositionWithOffset(index, (width - AndroidUtilities.dp(76.0f)) / 2);
        }
    }

    protected void showOptionsForTheme(Theme.ThemeInfo themeInfo) {
    }

    protected void presentFragment(BaseFragment fragment) {
    }

    protected void updateRows() {
    }
}
