package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.AccelerateInterpolator;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class StickerCell extends FrameLayout {
    private static AccelerateInterpolator interpolator = new AccelerateInterpolator(0.5f);
    private boolean clearsInputField;
    private BackupImageView imageView;
    private long lastUpdateTime;
    private Object parentObject;
    private float scale;
    private boolean scaled;
    private TLRPC.Document sticker;
    private long time;

    public StickerCell(Context context) {
        super(context);
        this.time = 0L;
        BackupImageView backupImageView = new BackupImageView(context);
        this.imageView = backupImageView;
        backupImageView.setAspectFit(true);
        this.imageView.setLayerNum(1);
        addView(this.imageView, LayoutHelper.createFrame(66.0f, 66.0f, 1, 0.0f, 5.0f, 0.0f, 0.0f));
        setFocusable(true);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(76.0f) + getPaddingLeft() + getPaddingRight(), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(78.0f), 1073741824));
    }

    @Override // android.view.View
    public void setPressed(boolean z) {
        if (this.imageView.getImageReceiver().getPressed() != z) {
            this.imageView.getImageReceiver().setPressed(z ? 1 : 0);
            this.imageView.invalidate();
        }
        super.setPressed(z);
    }

    public void setClearsInputField(boolean value) {
        this.clearsInputField = value;
    }

    public boolean isClearsInputField() {
        return this.clearsInputField;
    }

    public void setSticker(TLRPC.Document document, Object parent, int side) {
        this.parentObject = parent;
        if (document != null) {
            TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90);
            if (!MessageObject.canAutoplayAnimatedSticker(document)) {
                this.imageView.setImage(ImageLocation.getForDocument(thumb, document), (String) null, "webp", (Drawable) null, this.parentObject);
            } else if (thumb != null) {
                this.imageView.setImage(ImageLocation.getForDocument(document), "80_80", ImageLocation.getForDocument(thumb, document), null, 0, this.parentObject);
            } else {
                this.imageView.setImage(ImageLocation.getForDocument(document), "80_80", (String) null, (Drawable) null, this.parentObject);
            }
        }
        this.sticker = document;
        if (side == -1) {
            setBackgroundResource(R.drawable.stickers_back_left);
            setPadding(AndroidUtilities.dp(7.0f), 0, 0, 0);
        } else if (side == 0) {
            setBackgroundResource(R.drawable.stickers_back_center);
            setPadding(0, 0, 0, 0);
        } else if (side == 1) {
            setBackgroundResource(R.drawable.stickers_back_right);
            setPadding(0, 0, AndroidUtilities.dp(7.0f), 0);
        } else if (side == 2) {
            setBackgroundResource(R.drawable.stickers_back_all);
            setPadding(AndroidUtilities.dp(3.0f), 0, AndroidUtilities.dp(3.0f), 0);
        }
        Drawable background = getBackground();
        if (background != null) {
            background.setAlpha(230);
            background.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_stickersHintPanel), PorterDuff.Mode.MULTIPLY));
        }
    }

    public TLRPC.Document getSticker() {
        return this.sticker;
    }

    public Object getParentObject() {
        return this.parentObject;
    }

    public void setScaled(boolean value) {
        this.scaled = value;
        this.lastUpdateTime = System.currentTimeMillis();
        invalidate();
    }

    public boolean showingBitmap() {
        return this.imageView.getImageReceiver().getBitmap() != null;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0043  */
    @Override // android.view.ViewGroup
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected boolean drawChild(android.graphics.Canvas r11, android.view.View r12, long r13) {
        /*
            r10 = this;
            boolean r0 = super.drawChild(r11, r12, r13)
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r10.imageView
            if (r12 != r1) goto L66
            boolean r1 = r10.scaled
            r2 = 1065353216(0x3f800000, float:1.0)
            r3 = 1061997773(0x3f4ccccd, float:0.8)
            if (r1 == 0) goto L17
            float r1 = r10.scale
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 != 0) goto L21
        L17:
            boolean r1 = r10.scaled
            if (r1 != 0) goto L66
            float r1 = r10.scale
            int r1 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r1 == 0) goto L66
        L21:
            long r4 = java.lang.System.currentTimeMillis()
            long r6 = r10.lastUpdateTime
            long r6 = r4 - r6
            r10.lastUpdateTime = r4
            boolean r1 = r10.scaled
            r8 = 1137180672(0x43c80000, float:400.0)
            if (r1 == 0) goto L43
            float r1 = r10.scale
            int r9 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r9 == 0) goto L43
            float r2 = (float) r6
            float r2 = r2 / r8
            float r1 = r1 - r2
            r10.scale = r1
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 >= 0) goto L50
            r10.scale = r3
            goto L50
        L43:
            float r1 = r10.scale
            float r3 = (float) r6
            float r3 = r3 / r8
            float r1 = r1 + r3
            r10.scale = r1
            int r1 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r1 <= 0) goto L50
            r10.scale = r2
        L50:
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r10.imageView
            float r2 = r10.scale
            r1.setScaleX(r2)
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r10.imageView
            float r2 = r10.scale
            r1.setScaleY(r2)
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r10.imageView
            r1.invalidate()
            r10.invalidate()
        L66:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.StickerCell.drawChild(android.graphics.Canvas, android.view.View, long):boolean");
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        if (this.sticker == null) {
            return;
        }
        String emoji = null;
        for (int a = 0; a < this.sticker.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = this.sticker.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                emoji = (attribute.alt == null || attribute.alt.length() <= 0) ? null : attribute.alt;
            }
        }
        if (emoji != null) {
            info.setText(emoji + " " + LocaleController.getString("AttachSticker", R.string.AttachSticker));
        } else {
            info.setText(LocaleController.getString("AttachSticker", R.string.AttachSticker));
        }
        info.setEnabled(true);
    }
}
