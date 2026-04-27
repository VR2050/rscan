package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.graphics.Matrix;
import android.util.AttributeSet;
import android.view.TextureView;

/* JADX INFO: loaded from: classes5.dex */
public class ScaleTextureView extends TextureView {
    private Matrix mMatrix;
    private int mVideoHeight;
    private int mVideoWidth;

    public ScaleTextureView(Context context) {
        super(context);
        this.mMatrix = getMatrix();
    }

    public ScaleTextureView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mMatrix = getMatrix();
    }

    public void setmVideoWidth(int mVideoWidth) {
        this.mVideoWidth = mVideoWidth;
    }

    public void setmVideoHeight(int mVideoHeight) {
        this.mVideoHeight = mVideoHeight;
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int viewWidth = getDefaultSize(this.mVideoWidth, widthMeasureSpec);
        int viewHeight = getDefaultSize(this.mVideoHeight, heightMeasureSpec);
        setMeasuredDimension(viewWidth, viewHeight);
        float scaleX = (viewWidth * 1.0f) / this.mVideoWidth;
        float scaleY = (viewHeight * 1.0f) / this.mVideoHeight;
        float maxScale = Math.max(scaleX, scaleY);
        int pivotPointX = viewWidth / 2;
        int pivotPointY = viewHeight / 2;
        this.mMatrix.setScale(maxScale / scaleX, maxScale / scaleY, pivotPointX, pivotPointY);
        setTransform(this.mMatrix);
    }
}
