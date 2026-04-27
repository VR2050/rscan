package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.AccelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class StickerEmojiCell extends FrameLayout {
    private static AccelerateInterpolator interpolator = new AccelerateInterpolator(0.5f);
    private float alpha;
    private boolean changingAlpha;
    private int currentAccount;
    private TextView emojiTextView;
    private BackupImageView imageView;
    private long lastUpdateTime;
    private Object parentObject;
    private boolean recent;
    private float scale;
    private boolean scaled;
    private TLRPC.Document sticker;
    private long time;

    public StickerEmojiCell(Context context) {
        super(context);
        this.alpha = 1.0f;
        this.currentAccount = UserConfig.selectedAccount;
        BackupImageView backupImageView = new BackupImageView(context);
        this.imageView = backupImageView;
        backupImageView.setAspectFit(true);
        this.imageView.setLayerNum(1);
        addView(this.imageView, LayoutHelper.createFrame(66, 66, 17));
        TextView textView = new TextView(context);
        this.emojiTextView = textView;
        textView.setTextSize(1, 14.0f);
        addView(this.emojiTextView, LayoutHelper.createFrame(28, 28, 85));
        setFocusable(true);
    }

    public TLRPC.Document getSticker() {
        return this.sticker;
    }

    public Object getParentObject() {
        return this.parentObject;
    }

    public boolean isRecent() {
        return this.recent;
    }

    public void setRecent(boolean value) {
        this.recent = value;
    }

    public void setSticker(TLRPC.Document document, Object parent, boolean showEmoji) {
        setSticker(document, parent, null, showEmoji);
    }

    public void setSticker(TLRPC.Document document, Object parent, String emoji, boolean showEmoji) {
        if (document != null) {
            this.sticker = document;
            this.parentObject = parent;
            TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90);
            if (MessageObject.canAutoplayAnimatedSticker(document)) {
                if (thumb != null) {
                    this.imageView.setImage(ImageLocation.getForDocument(document), "80_80", ImageLocation.getForDocument(thumb, document), null, 0, this.parentObject);
                } else {
                    this.imageView.setImage(ImageLocation.getForDocument(document), "80_80", (String) null, (Drawable) null, this.parentObject);
                }
            } else if (thumb != null) {
                this.imageView.setImage(ImageLocation.getForDocument(thumb, document), (String) null, "webp", (Drawable) null, this.parentObject);
            } else {
                this.imageView.setImage(ImageLocation.getForDocument(document), (String) null, "webp", (Drawable) null, this.parentObject);
            }
            if (emoji != null) {
                TextView textView = this.emojiTextView;
                textView.setText(Emoji.replaceEmoji(emoji, textView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(16.0f), false));
                this.emojiTextView.setVisibility(0);
                return;
            }
            if (showEmoji) {
                boolean set = false;
                int a = 0;
                while (true) {
                    if (a >= document.attributes.size()) {
                        break;
                    }
                    TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                    if (!(attribute instanceof TLRPC.TL_documentAttributeSticker)) {
                        a++;
                    } else if (attribute.alt != null && attribute.alt.length() > 0) {
                        this.emojiTextView.setText(Emoji.replaceEmoji(attribute.alt, this.emojiTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(16.0f), false));
                        set = true;
                    }
                }
                if (!set) {
                    this.emojiTextView.setText(Emoji.replaceEmoji(MediaDataController.getInstance(this.currentAccount).getEmojiForSticker(this.sticker.id), this.emojiTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(16.0f), false));
                }
                this.emojiTextView.setVisibility(0);
                return;
            }
            this.emojiTextView.setVisibility(4);
        }
    }

    public void disable() {
        this.changingAlpha = true;
        this.alpha = 0.5f;
        this.time = 0L;
        this.imageView.getImageReceiver().setAlpha(this.alpha);
        this.imageView.invalidate();
        this.lastUpdateTime = System.currentTimeMillis();
        invalidate();
    }

    public void setScaled(boolean value) {
        this.scaled = value;
        this.lastUpdateTime = System.currentTimeMillis();
        invalidate();
    }

    public boolean isDisabled() {
        return this.changingAlpha;
    }

    public boolean showingBitmap() {
        return this.imageView.getImageReceiver().getBitmap() != null;
    }

    public BackupImageView getImageView() {
        return this.imageView;
    }

    @Override // android.view.View
    public void invalidate() {
        this.emojiTextView.invalidate();
        super.invalidate();
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0081  */
    @Override // android.view.ViewGroup
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected boolean drawChild(android.graphics.Canvas r12, android.view.View r13, long r14) {
        /*
            r11 = this;
            boolean r0 = super.drawChild(r12, r13, r14)
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r11.imageView
            if (r13 != r1) goto La4
            boolean r1 = r11.changingAlpha
            r2 = 1061997773(0x3f4ccccd, float:0.8)
            r3 = 1065353216(0x3f800000, float:1.0)
            if (r1 != 0) goto L25
            boolean r1 = r11.scaled
            if (r1 == 0) goto L1b
            float r1 = r11.scale
            int r1 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r1 != 0) goto L25
        L1b:
            boolean r1 = r11.scaled
            if (r1 != 0) goto La4
            float r1 = r11.scale
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 == 0) goto La4
        L25:
            long r4 = java.lang.System.currentTimeMillis()
            long r6 = r11.lastUpdateTime
            long r6 = r4 - r6
            r11.lastUpdateTime = r4
            boolean r1 = r11.changingAlpha
            if (r1 == 0) goto L69
            long r1 = r11.time
            long r1 = r1 + r6
            r11.time = r1
            r8 = 1050(0x41a, double:5.19E-321)
            int r10 = (r1 > r8 ? 1 : (r1 == r8 ? 0 : -1))
            if (r10 <= 0) goto L40
            r11.time = r8
        L40:
            android.view.animation.AccelerateInterpolator r1 = im.uwrkaxlmjj.ui.cells.StickerEmojiCell.interpolator
            long r8 = r11.time
            float r2 = (float) r8
            r8 = 1149452288(0x44834000, float:1050.0)
            float r2 = r2 / r8
            float r1 = r1.getInterpolation(r2)
            r2 = 1056964608(0x3f000000, float:0.5)
            float r1 = r1 * r2
            float r1 = r1 + r2
            r11.alpha = r1
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 < 0) goto L5d
            r1 = 0
            r11.changingAlpha = r1
            r11.alpha = r3
        L5d:
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r11.imageView
            im.uwrkaxlmjj.messenger.ImageReceiver r1 = r1.getImageReceiver()
            float r2 = r11.alpha
            r1.setAlpha(r2)
            goto L8e
        L69:
            boolean r1 = r11.scaled
            r8 = 1137180672(0x43c80000, float:400.0)
            if (r1 == 0) goto L81
            float r1 = r11.scale
            int r9 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r9 == 0) goto L81
            float r3 = (float) r6
            float r3 = r3 / r8
            float r1 = r1 - r3
            r11.scale = r1
            int r1 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r1 >= 0) goto L8e
            r11.scale = r2
            goto L8e
        L81:
            float r1 = r11.scale
            float r2 = (float) r6
            float r2 = r2 / r8
            float r1 = r1 + r2
            r11.scale = r1
            int r1 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r1 <= 0) goto L8e
            r11.scale = r3
        L8e:
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r11.imageView
            float r2 = r11.scale
            r1.setScaleX(r2)
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r11.imageView
            float r2 = r11.scale
            r1.setScaleY(r2)
            im.uwrkaxlmjj.ui.components.BackupImageView r1 = r11.imageView
            r1.invalidate()
            r11.invalidate()
        La4:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.StickerEmojiCell.drawChild(android.graphics.Canvas, android.view.View, long):boolean");
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        String descr = LocaleController.getString("AttachSticker", R.string.AttachSticker);
        int a = 0;
        while (true) {
            if (a >= this.sticker.attributes.size()) {
                break;
            }
            TLRPC.DocumentAttribute attribute = this.sticker.attributes.get(a);
            if (!(attribute instanceof TLRPC.TL_documentAttributeSticker)) {
                a++;
            } else if (attribute.alt != null && attribute.alt.length() > 0) {
                this.emojiTextView.setText(Emoji.replaceEmoji(attribute.alt, this.emojiTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(16.0f), false));
                descr = attribute.alt + " " + descr;
            }
        }
        info.setContentDescription(descr);
        info.setEnabled(true);
    }
}
