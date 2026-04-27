package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.widget;

import android.content.Context;
import android.view.TextureView;
import android.view.View;

/* JADX INFO: loaded from: classes5.dex */
public class NiceTextureView extends TextureView {
    private int videoHeight;
    private int videoWidth;

    public NiceTextureView(Context context) {
        super(context);
    }

    public void adaptVideoSize(int videoWidth, int videoHeight) {
        if (this.videoWidth != videoWidth && this.videoHeight != videoHeight) {
            this.videoWidth = videoWidth;
            this.videoHeight = videoHeight;
            requestLayout();
        }
    }

    @Override // android.view.View
    public void setRotation(float rotation) {
        if (rotation != getRotation()) {
            super.setRotation(rotation);
            requestLayout();
        }
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        float viewRotation = getRotation();
        if (viewRotation == 90.0f || viewRotation == 270.0f) {
            widthMeasureSpec = heightMeasureSpec;
            heightMeasureSpec = widthMeasureSpec;
        }
        int tempMeasureSpec = this.videoWidth;
        int width = getDefaultSize(tempMeasureSpec, widthMeasureSpec);
        int height = getDefaultSize(this.videoHeight, heightMeasureSpec);
        if (this.videoWidth > 0 && this.videoHeight > 0) {
            int widthSpecMode = View.MeasureSpec.getMode(widthMeasureSpec);
            int widthSpecSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSpecMode = View.MeasureSpec.getMode(heightMeasureSpec);
            int heightSpecSize = View.MeasureSpec.getSize(heightMeasureSpec);
            if (widthSpecMode != 1073741824 || heightSpecMode != 1073741824) {
                if (widthSpecMode == 1073741824) {
                    width = widthSpecSize;
                    int i = this.videoHeight;
                    int i2 = this.videoWidth;
                    height = (width * i) / i2;
                    if (heightSpecMode == Integer.MIN_VALUE && height > heightSpecSize) {
                        height = heightSpecSize;
                        width = (i2 * height) / i;
                    }
                } else if (heightSpecMode == 1073741824) {
                    height = heightSpecSize;
                    int i3 = this.videoWidth;
                    int i4 = this.videoHeight;
                    width = (height * i3) / i4;
                    if (widthSpecMode == Integer.MIN_VALUE && width > widthSpecSize) {
                        width = widthSpecSize;
                        height = (i4 * width) / i3;
                    }
                } else {
                    width = this.videoWidth;
                    height = this.videoHeight;
                    if (heightSpecMode == Integer.MIN_VALUE && height > heightSpecSize) {
                        height = heightSpecSize;
                        width = (this.videoWidth * height) / this.videoHeight;
                    }
                    if (widthSpecMode == Integer.MIN_VALUE && width > widthSpecSize) {
                        width = widthSpecSize;
                        height = (this.videoHeight * width) / this.videoWidth;
                    }
                }
            } else {
                width = widthSpecSize;
                height = heightSpecSize;
                int i5 = this.videoWidth;
                int i6 = i5 * height;
                int i7 = this.videoHeight;
                if (i6 < width * i7) {
                    width = (i5 * height) / i7;
                } else if (i5 * height > width * i7) {
                    height = (i7 * width) / i5;
                }
            }
        }
        setMeasuredDimension(width, height);
    }
}
