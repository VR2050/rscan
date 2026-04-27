package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Bitmap;
import android.os.Build;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.components.crop.CropRotationWheel;
import im.uwrkaxlmjj.ui.components.crop.CropView;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoCropView extends FrameLayout {
    private CropView cropView;
    private PhotoCropViewDelegate delegate;
    boolean isFcCrop;
    private boolean showOnSetBitmap;
    private CropRotationWheel wheelView;

    public interface PhotoCropViewDelegate {
        void onChange(boolean z);
    }

    public PhotoCropView(Context context) {
        super(context);
        CropView cropView = new CropView(getContext());
        this.cropView = cropView;
        cropView.setListener(new CropView.CropViewListener() { // from class: im.uwrkaxlmjj.ui.components.PhotoCropView.1
            @Override // im.uwrkaxlmjj.ui.components.crop.CropView.CropViewListener
            public void onChange(boolean reset) {
                if (PhotoCropView.this.delegate != null) {
                    PhotoCropView.this.delegate.onChange(reset);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropView.CropViewListener
            public void onAspectLock(boolean enabled) {
                PhotoCropView.this.wheelView.setAspectLock(enabled);
            }
        });
        this.cropView.setBottomPadding(AndroidUtilities.dp(64.0f));
        addView(this.cropView);
        CropRotationWheel cropRotationWheel = new CropRotationWheel(getContext());
        this.wheelView = cropRotationWheel;
        cropRotationWheel.setListener(new CropRotationWheel.RotationWheelListener() { // from class: im.uwrkaxlmjj.ui.components.PhotoCropView.2
            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void onStart() {
                PhotoCropView.this.cropView.onRotationBegan();
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void onChange(float angle) {
                PhotoCropView.this.cropView.setRotation(angle);
                if (PhotoCropView.this.delegate != null) {
                    PhotoCropView.this.delegate.onChange(false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void onEnd(float angle) {
                PhotoCropView.this.cropView.onRotationEnded();
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void aspectRatioPressed() {
                PhotoCropView.this.cropView.showAspectRatioDialog();
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void rotate90Pressed() {
                PhotoCropView.this.rotate();
            }
        });
        addView(this.wheelView, LayoutHelper.createFrame(-1.0f, -2.0f, 81, 0.0f, 0.0f, 0.0f, 0.0f));
    }

    public boolean isFcCrop() {
        return this.isFcCrop;
    }

    public PhotoCropView(Context context, boolean isFcCrop) {
        super(context);
        this.isFcCrop = isFcCrop;
        if (isFcCrop) {
            this.cropView = new CropView(getContext(), true);
        } else {
            this.cropView = new CropView(getContext());
        }
        this.cropView.setListener(new CropView.CropViewListener() { // from class: im.uwrkaxlmjj.ui.components.PhotoCropView.3
            @Override // im.uwrkaxlmjj.ui.components.crop.CropView.CropViewListener
            public void onChange(boolean reset) {
                if (PhotoCropView.this.delegate != null) {
                    PhotoCropView.this.delegate.onChange(reset);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropView.CropViewListener
            public void onAspectLock(boolean enabled) {
                PhotoCropView.this.wheelView.setAspectLock(enabled);
            }
        });
        this.cropView.setBottomPadding(AndroidUtilities.dp(64.0f));
        addView(this.cropView);
        CropRotationWheel cropRotationWheel = new CropRotationWheel(getContext());
        this.wheelView = cropRotationWheel;
        cropRotationWheel.setListener(new CropRotationWheel.RotationWheelListener() { // from class: im.uwrkaxlmjj.ui.components.PhotoCropView.4
            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void onStart() {
                PhotoCropView.this.cropView.onRotationBegan();
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void onChange(float angle) {
                PhotoCropView.this.cropView.setRotation(angle);
                if (PhotoCropView.this.delegate != null) {
                    PhotoCropView.this.delegate.onChange(false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void onEnd(float angle) {
                PhotoCropView.this.cropView.onRotationEnded();
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void aspectRatioPressed() {
                PhotoCropView.this.cropView.showAspectRatioDialog();
            }

            @Override // im.uwrkaxlmjj.ui.components.crop.CropRotationWheel.RotationWheelListener
            public void rotate90Pressed() {
                PhotoCropView.this.rotate();
            }
        });
        addView(this.wheelView, LayoutHelper.createFrame(-1.0f, -2.0f, 81, 0.0f, 0.0f, 0.0f, 0.0f));
    }

    public void rotate() {
        CropRotationWheel cropRotationWheel = this.wheelView;
        if (cropRotationWheel != null) {
            cropRotationWheel.reset();
        }
        this.cropView.rotate90Degrees();
    }

    public void setBitmap(Bitmap bitmap, int rotation, boolean freeform, boolean update) {
        requestLayout();
        this.cropView.setBitmap(bitmap, rotation, freeform, update);
        if (this.showOnSetBitmap) {
            this.showOnSetBitmap = false;
            this.cropView.show();
        }
        this.wheelView.setFreeform(freeform);
        this.wheelView.reset();
        this.wheelView.setVisibility(freeform ? 0 : 4);
    }

    public boolean isReady() {
        return this.cropView.isReady();
    }

    public void reset() {
        this.wheelView.reset();
        this.cropView.reset();
    }

    public void onAppear() {
        this.cropView.willShow();
    }

    public void setAspectRatio(float ratio) {
        this.cropView.setAspectRatio(ratio);
    }

    public void hideBackView() {
        this.cropView.hideBackView();
    }

    public void showBackView() {
        this.cropView.showBackView();
    }

    public void setFreeform(boolean freeform) {
        this.cropView.setFreeform(freeform);
    }

    public void onAppeared() {
        CropView cropView = this.cropView;
        if (cropView != null) {
            cropView.show();
        } else {
            this.showOnSetBitmap = true;
        }
    }

    public void onDisappear() {
        CropView cropView = this.cropView;
        if (cropView != null) {
            cropView.hide();
        }
    }

    public float getRectX() {
        return this.cropView.getCropLeft() - AndroidUtilities.dp(14.0f);
    }

    public float getRectY() {
        return (this.cropView.getCropTop() - AndroidUtilities.dp(14.0f)) - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
    }

    public float getRectSizeX() {
        return this.cropView.getCropWidth();
    }

    public float getRectSizeY() {
        return this.cropView.getCropHeight();
    }

    public Bitmap getBitmap() {
        CropView cropView = this.cropView;
        if (cropView != null) {
            return cropView.getResult();
        }
        return null;
    }

    public void setDelegate(PhotoCropViewDelegate delegate) {
        this.delegate = delegate;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        CropView cropView = this.cropView;
        if (cropView != null) {
            cropView.updateLayout();
        }
    }
}
