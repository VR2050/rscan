package androidx.camera.view;

import android.graphics.Bitmap;
import android.util.Size;
import android.view.View;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.SurfaceRequest;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public abstract class PreviewViewImplementation {

    @NonNull
    public FrameLayout mParent;

    @NonNull
    private final PreviewTransformation mPreviewTransform;

    @Nullable
    public Size mResolution;

    public interface OnSurfaceNotInUseListener {
        void onSurfaceNotInUse();
    }

    public PreviewViewImplementation(@NonNull FrameLayout frameLayout, @NonNull PreviewTransformation previewTransformation) {
        this.mParent = frameLayout;
        this.mPreviewTransform = previewTransformation;
    }

    @Nullable
    public Bitmap getBitmap() {
        Bitmap previewBitmap = getPreviewBitmap();
        if (previewBitmap == null) {
            return null;
        }
        return this.mPreviewTransform.createTransformedBitmap(previewBitmap, new Size(this.mParent.getWidth(), this.mParent.getHeight()), this.mParent.getLayoutDirection());
    }

    @Nullable
    public abstract View getPreview();

    @Nullable
    public abstract Bitmap getPreviewBitmap();

    public abstract void initializePreview();

    public abstract void onAttachedToWindow();

    public abstract void onDetachedFromWindow();

    public void onSurfaceProvided() {
        redrawPreview();
    }

    public abstract void onSurfaceRequested(@NonNull SurfaceRequest surfaceRequest, @Nullable OnSurfaceNotInUseListener onSurfaceNotInUseListener);

    public void redrawPreview() {
        View preview = getPreview();
        if (preview == null) {
            return;
        }
        this.mPreviewTransform.transformView(new Size(this.mParent.getWidth(), this.mParent.getHeight()), this.mParent.getLayoutDirection(), preview);
    }

    @NonNull
    public abstract InterfaceFutureC2413a<Void> waitForNextFrame();
}
