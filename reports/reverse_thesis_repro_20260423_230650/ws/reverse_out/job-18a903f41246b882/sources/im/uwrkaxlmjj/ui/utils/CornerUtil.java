package im.uwrkaxlmjj.ui.utils;

import android.graphics.Canvas;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.view.View;
import android.view.ViewOutlineProvider;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class CornerUtil {
    private boolean clicpWithPadding;
    public int color;
    private float[] conrnerDii;
    public float radius;
    public float radiusBottom;
    public float radiusLeft;
    public float radiusRight;
    public float radiusTop;
    private View view;
    public float strokeWidth = AndroidUtilities.dp(2.0f);
    private Path path = new Path();
    private Paint paint = new Paint(1);
    private Paint.Style paintStyle = Paint.Style.FILL;
    public RectF rectF = new RectF();

    public CornerUtil(View view) {
        this.view = view;
    }

    public void onDraw(Canvas canvas) {
        if (this.view == null || canvas == null) {
            return;
        }
        if (this.radius > 0.0f || this.radiusLeft > 0.0f || this.radiusTop > 0.0f || this.radiusRight > 0.0f || this.radiusBottom > 0.0f) {
            this.rectF.left = this.clicpWithPadding ? this.view.getLeft() - this.view.getPaddingLeft() : this.view.getLeft();
            this.rectF.top = this.clicpWithPadding ? this.view.getTop() - this.view.getPaddingTop() : this.view.getTop();
            this.rectF.right = this.clicpWithPadding ? this.view.getRight() - this.view.getPaddingRight() : this.view.getRight();
            this.rectF.bottom = this.clicpWithPadding ? this.view.getBottom() - this.view.getPaddingBottom() : this.view.getBottom();
            if (this.radiusLeft > 0.0f || this.radiusTop > 0.0f || this.radiusRight > 0.0f || this.radiusBottom > 0.0f) {
                if (this.conrnerDii == null) {
                    float f = this.radiusLeft;
                    float f2 = this.radiusTop;
                    float f3 = this.radiusRight;
                    float f4 = this.radiusBottom;
                    this.conrnerDii = new float[]{f, f, f2, f2, f3, f3, f4, f4};
                }
                this.path.addRoundRect(this.rectF, this.conrnerDii, Path.Direction.CCW);
            } else {
                Path path = this.path;
                RectF rectF = this.rectF;
                float f5 = this.radius;
                path.addRoundRect(rectF, f5, f5, Path.Direction.CCW);
            }
            reset();
            canvas.clipPath(this.path);
        }
    }

    private void reset() {
        if (this.color != this.paint.getColor() || this.strokeWidth != this.paint.getStrokeWidth() || this.paintStyle != this.paint.getStyle()) {
            this.paint.setColor(this.color);
            this.paint.setStrokeWidth(this.strokeWidth);
            this.paint.setStyle(this.paintStyle);
        }
    }

    public static void clipViewCircle(View view) {
        view.setClipToOutline(true);
        view.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.utils.CornerUtil.1
            @Override // android.view.ViewOutlineProvider
            public void getOutline(View view2, Outline outline) {
                outline.setOval(0, 0, view2.getWidth(), view2.getHeight());
            }
        });
    }

    public static void clipViewCornerByDp(View view, final int pixel) {
        view.setClipToOutline(true);
        view.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.utils.CornerUtil.2
            @Override // android.view.ViewOutlineProvider
            public void getOutline(View view2, Outline outline) {
                outline.setRoundRect(0, 0, view2.getWidth(), view2.getHeight(), pixel);
            }
        });
    }
}
