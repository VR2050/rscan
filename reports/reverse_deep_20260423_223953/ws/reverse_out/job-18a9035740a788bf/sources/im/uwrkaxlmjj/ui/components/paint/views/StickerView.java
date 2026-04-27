package im.uwrkaxlmjj.ui.components.paint.views;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.Point;
import im.uwrkaxlmjj.ui.components.Rect;
import im.uwrkaxlmjj.ui.components.Size;
import im.uwrkaxlmjj.ui.components.paint.views.EntityView;

/* JADX INFO: loaded from: classes5.dex */
public class StickerView extends EntityView {
    private int anchor;
    private Size baseSize;
    private ImageReceiver centerImage;
    private FrameLayoutDrawer containerView;
    private boolean mirrored;
    private Object parentObject;
    private TLRPC.Document sticker;

    private class FrameLayoutDrawer extends FrameLayout {
        public FrameLayoutDrawer(Context context) {
            super(context);
            setWillNotDraw(false);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            StickerView.this.stickerDraw(canvas);
        }
    }

    public StickerView(Context context, Point position, Size baseSize, TLRPC.Document sticker, Object parentObject) {
        this(context, position, 0.0f, 1.0f, baseSize, sticker, parentObject);
    }

    public StickerView(Context context, Point position, float angle, float scale, Size baseSize, TLRPC.Document sticker, Object parentObject) {
        super(context, position);
        this.anchor = -1;
        this.mirrored = false;
        this.centerImage = new ImageReceiver();
        setRotation(angle);
        setScale(scale);
        this.sticker = sticker;
        this.baseSize = baseSize;
        this.parentObject = parentObject;
        int a = 0;
        while (true) {
            if (a >= sticker.attributes.size()) {
                break;
            }
            TLRPC.DocumentAttribute attribute = sticker.attributes.get(a);
            if (!(attribute instanceof TLRPC.TL_documentAttributeSticker)) {
                a++;
            } else if (attribute.mask_coords != null) {
                this.anchor = attribute.mask_coords.n;
            }
        }
        FrameLayoutDrawer frameLayoutDrawer = new FrameLayoutDrawer(context);
        this.containerView = frameLayoutDrawer;
        addView(frameLayoutDrawer, LayoutHelper.createFrame(-1, -1.0f));
        this.centerImage.setAspectFit(true);
        this.centerImage.setInvalidateAll(true);
        this.centerImage.setParentView(this.containerView);
        TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(sticker.thumbs, 90);
        this.centerImage.setImage(ImageLocation.getForDocument(sticker), (String) null, ImageLocation.getForDocument(thumb, sticker), (String) null, "webp", parentObject, 1);
        updatePosition();
    }

    public StickerView(Context context, StickerView stickerView, Point position) {
        this(context, position, stickerView.getRotation(), stickerView.getScale(), stickerView.baseSize, stickerView.sticker, stickerView.parentObject);
        if (stickerView.mirrored) {
            mirror();
        }
    }

    public int getAnchor() {
        return this.anchor;
    }

    public void mirror() {
        this.mirrored = !this.mirrored;
        this.containerView.invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView
    protected void updatePosition() {
        float halfWidth = this.baseSize.width / 2.0f;
        float halfHeight = this.baseSize.height / 2.0f;
        setX(this.position.x - halfWidth);
        setY(this.position.y - halfHeight);
        updateSelectionView();
    }

    protected void stickerDraw(Canvas canvas) {
        if (this.containerView == null) {
            return;
        }
        canvas.save();
        Bitmap bitmap = this.centerImage.getBitmap();
        if (bitmap != null) {
            if (this.mirrored) {
                canvas.scale(-1.0f, 1.0f);
                canvas.translate(-this.baseSize.width, 0.0f);
            }
            this.centerImage.setImageCoords(0, 0, (int) this.baseSize.width, (int) this.baseSize.height);
            this.centerImage.draw(canvas);
        }
        canvas.restore();
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec((int) this.baseSize.width, 1073741824), View.MeasureSpec.makeMeasureSpec((int) this.baseSize.height, 1073741824));
    }

    @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView
    protected Rect getSelectionBounds() {
        ViewGroup parentView = (ViewGroup) getParent();
        float scale = parentView.getScaleX();
        float side = getWidth() * (getScale() + 0.4f);
        return new Rect((this.position.x - (side / 2.0f)) * scale, (this.position.y - (side / 2.0f)) * scale, side * scale, side * scale);
    }

    @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView
    protected EntityView.SelectionView createSelectionView() {
        return new StickerViewSelectionView(getContext());
    }

    public TLRPC.Document getSticker() {
        return this.sticker;
    }

    public class StickerViewSelectionView extends EntityView.SelectionView {
        private Paint arcPaint;
        private RectF arcRect;

        public StickerViewSelectionView(Context context) {
            super(context);
            this.arcPaint = new Paint(1);
            this.arcRect = new RectF();
            this.arcPaint.setColor(-1);
            this.arcPaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
            this.arcPaint.setStyle(Paint.Style.STROKE);
        }

        @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView.SelectionView
        protected int pointInsideHandle(float x, float y) {
            float thickness = AndroidUtilities.dp(1.0f);
            float radius = AndroidUtilities.dp(19.5f);
            float inset = radius + thickness;
            float middle = ((getHeight() - (inset * 2.0f)) / 2.0f) + inset;
            if (x > inset - radius && y > middle - radius && x < inset + radius && y < middle + radius) {
                return 1;
            }
            if (x > ((getWidth() - (inset * 2.0f)) + inset) - radius && y > middle - radius && x < (getWidth() - (inset * 2.0f)) + inset + radius && y < middle + radius) {
                return 2;
            }
            float selectionRadius = getWidth() / 2.0f;
            if (Math.pow(x - selectionRadius, 2.0d) + Math.pow(y - selectionRadius, 2.0d) < Math.pow(selectionRadius, 2.0d)) {
                return 3;
            }
            return 0;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float thickness = AndroidUtilities.dp(1.0f);
            float radius = AndroidUtilities.dp(4.5f);
            float inset = radius + thickness + AndroidUtilities.dp(15.0f);
            float mainRadius = (getWidth() / 2) - inset;
            this.arcRect.set(inset, inset, (mainRadius * 2.0f) + inset, (mainRadius * 2.0f) + inset);
            for (int i = 0; i < 48; i++) {
                canvas.drawArc(this.arcRect, (4.0f + 4.0f) * i, 4.0f, false, this.arcPaint);
            }
            canvas.drawCircle(inset, inset + mainRadius, radius, this.dotPaint);
            canvas.drawCircle(inset, inset + mainRadius, radius, this.dotStrokePaint);
            canvas.drawCircle((mainRadius * 2.0f) + inset, inset + mainRadius, radius, this.dotPaint);
            canvas.drawCircle((2.0f * mainRadius) + inset, inset + mainRadius, radius, this.dotStrokePaint);
        }
    }
}
