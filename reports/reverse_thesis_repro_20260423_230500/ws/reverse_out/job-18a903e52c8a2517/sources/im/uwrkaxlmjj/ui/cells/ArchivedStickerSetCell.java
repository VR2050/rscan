package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.Switch;

/* JADX INFO: loaded from: classes5.dex */
public class ArchivedStickerSetCell extends FrameLayout {
    private Switch checkBox;
    private BackupImageView imageView;
    private boolean needDivider;
    private Switch.OnCheckedChangeListener onCheckedChangeListener;
    private Rect rect;
    private TLRPC.StickerSetCovered stickersSet;
    private TextView textView;
    private TextView valueTextView;

    public ArchivedStickerSetCell(Context context, boolean needCheckBox) {
        super(context);
        this.rect = new Rect();
        TextView textView = new TextView(context);
        this.textView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.textView.setTextSize(1, 14.0f);
        this.textView.setLines(1);
        this.textView.setMaxLines(1);
        this.textView.setSingleLine(true);
        this.textView.setEllipsize(TextUtils.TruncateAt.END);
        this.textView.setGravity(LocaleController.isRTL ? 5 : 3);
        addView(this.textView, LayoutHelper.createFrame(-2.0f, -2.0f, LocaleController.isRTL ? 5 : 3, 71.0f, 10.0f, needCheckBox ? 71.0f : 21.0f, 0.0f));
        TextView textView2 = new TextView(context);
        this.valueTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
        this.valueTextView.setTextSize(1, 13.0f);
        this.valueTextView.setLines(1);
        this.valueTextView.setMaxLines(1);
        this.valueTextView.setSingleLine(true);
        this.valueTextView.setGravity(LocaleController.isRTL ? 5 : 3);
        addView(this.valueTextView, LayoutHelper.createFrame(-2.0f, -2.0f, LocaleController.isRTL ? 5 : 3, 71.0f, 35.0f, needCheckBox ? 71.0f : 21.0f, 0.0f));
        BackupImageView backupImageView = new BackupImageView(context);
        this.imageView = backupImageView;
        backupImageView.setAspectFit(true);
        this.imageView.setLayerNum(1);
        addView(this.imageView, LayoutHelper.createFrame(48.0f, 48.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0.0f : 12.0f, 8.0f, LocaleController.isRTL ? 12.0f : 0.0f, 0.0f));
        if (needCheckBox) {
            Switch r0 = new Switch(context);
            this.checkBox = r0;
            r0.setColors(Theme.key_switchTrack, Theme.key_switchTrackChecked, Theme.key_windowBackgroundWhite, Theme.key_windowBackgroundWhite);
            addView(this.checkBox, LayoutHelper.createFrame(37.0f, 40.0f, (LocaleController.isRTL ? 3 : 5) | 16, 16.0f, 0.0f, 16.0f, 0.0f));
        }
    }

    public TextView getTextView() {
        return this.textView;
    }

    public TextView getValueTextView() {
        return this.valueTextView;
    }

    public Switch getCheckBox() {
        return this.checkBox;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(i), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(64.0f) + (this.needDivider ? 1 : 0), 1073741824));
    }

    public void setStickersSet(TLRPC.StickerSetCovered set, boolean divider) {
        TLRPC.Document sticker;
        TLObject object;
        ImageLocation imageLocation;
        this.needDivider = divider;
        this.stickersSet = set;
        setWillNotDraw(!divider);
        this.textView.setText(this.stickersSet.set.title);
        this.valueTextView.setText(LocaleController.formatPluralString("Stickers", set.set.count));
        if (set.cover != null) {
            sticker = set.cover;
        } else if (!set.covers.isEmpty()) {
            sticker = set.covers.get(0);
        } else {
            sticker = null;
        }
        if (sticker != null) {
            if (set.set.thumb instanceof TLRPC.TL_photoSize) {
                object = set.set.thumb;
            } else {
                TLObject object2 = sticker;
                object = object2;
            }
            if (object instanceof TLRPC.Document) {
                TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(sticker.thumbs, 90);
                ImageLocation imageLocation2 = ImageLocation.getForDocument(thumb, sticker);
                imageLocation = imageLocation2;
            } else {
                TLRPC.PhotoSize thumb2 = (TLRPC.PhotoSize) object;
                imageLocation = ImageLocation.getForSticker(thumb2, sticker);
            }
            if ((object instanceof TLRPC.Document) && MessageObject.isAnimatedStickerDocument(sticker)) {
                this.imageView.setImage(ImageLocation.getForDocument(sticker), "50_50", imageLocation, null, 0, set);
                return;
            } else if (imageLocation != null && imageLocation.lottieAnimation) {
                this.imageView.setImage(imageLocation, "50_50", "tgs", (Drawable) null, set);
                return;
            } else {
                this.imageView.setImage(imageLocation, "50_50", "webp", (Drawable) null, set);
                return;
            }
        }
        this.imageView.setImage((ImageLocation) null, (String) null, "webp", (Drawable) null, set);
    }

    public void setOnCheckClick(Switch.OnCheckedChangeListener listener) {
        Switch r0 = this.checkBox;
        this.onCheckedChangeListener = listener;
        r0.setOnCheckedChangeListener(listener);
        this.checkBox.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ArchivedStickerSetCell$2lcg2V3-MJbLynWgqwuxOfUooQQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setOnCheckClick$0$ArchivedStickerSetCell(view);
            }
        });
    }

    public /* synthetic */ void lambda$setOnCheckClick$0$ArchivedStickerSetCell(View v) {
        this.checkBox.setChecked(!r0.isChecked(), true);
    }

    public void setChecked(boolean checked) {
        this.checkBox.setOnCheckedChangeListener(null);
        this.checkBox.setChecked(checked, true);
        this.checkBox.setOnCheckedChangeListener(this.onCheckedChangeListener);
    }

    public boolean isChecked() {
        Switch r0 = this.checkBox;
        return r0 != null && r0.isChecked();
    }

    public TLRPC.StickerSetCovered getStickersSet() {
        return this.stickersSet;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        Switch r0 = this.checkBox;
        if (r0 != null) {
            r0.getHitRect(this.rect);
            if (this.rect.contains((int) event.getX(), (int) event.getY())) {
                event.offsetLocation(-this.checkBox.getX(), -this.checkBox.getY());
                return this.checkBox.onTouchEvent(event);
            }
        }
        return super.onTouchEvent(event);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (this.needDivider) {
            canvas.drawLine(0.0f, getHeight() - 1, getWidth() - getPaddingRight(), getHeight() - 1, Theme.dividerPaint);
        }
    }
}
