package com.jbzd.media.movecartoons.p396ui.dialog;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import androidx.annotation.NonNull;
import androidx.annotation.StyleRes;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public class StrongBottomSheetDialog extends BottomSheetDialog {
    private BottomSheetBehavior mBottomSheetBehavior;
    private final BottomSheetBehavior.BottomSheetCallback mBottomSheetCallback;
    private boolean mCreated;
    private int mMaxHeight;
    private int mPeekHeight;
    private Window mWindow;

    public StrongBottomSheetDialog(@NonNull Context context) {
        super(context);
        this.mBottomSheetCallback = new BottomSheetBehavior.BottomSheetCallback() { // from class: com.jbzd.media.movecartoons.ui.dialog.StrongBottomSheetDialog.1
            @Override // com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback
            public void onSlide(@NonNull View view, float f2) {
            }

            @Override // com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback
            public void onStateChanged(@NonNull View view, int i2) {
                if (i2 == 5) {
                    StrongBottomSheetDialog.this.dismiss();
                    BottomSheetBehavior.from(view).setState(4);
                }
            }
        };
        this.mWindow = getWindow();
    }

    private BottomSheetBehavior getBottomSheetBehavior() {
        BottomSheetBehavior bottomSheetBehavior = this.mBottomSheetBehavior;
        if (bottomSheetBehavior != null) {
            return bottomSheetBehavior;
        }
        View findViewById = this.mWindow.findViewById(R.id.design_bottom_sheet);
        if (findViewById == null) {
            return null;
        }
        BottomSheetBehavior from = BottomSheetBehavior.from(findViewById);
        this.mBottomSheetBehavior = from;
        return from;
    }

    private void setBottomSheetCallback() {
        if (getBottomSheetBehavior() != null) {
            this.mBottomSheetBehavior.setBottomSheetCallback(this.mBottomSheetCallback);
        }
    }

    @Override // com.google.android.material.bottomsheet.BottomSheetDialog, androidx.appcompat.app.AppCompatDialog, android.app.Dialog
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.mCreated = true;
        setPeekHeight();
        setMaxHeight();
        setBottomSheetCallback();
    }

    public void setBatterSwipeDismiss(boolean z) {
    }

    public void setMaxHeight(int i2) {
        this.mMaxHeight = i2;
        if (this.mCreated) {
            setMaxHeight();
        }
    }

    public void setPeekHeight(int i2) {
        this.mPeekHeight = i2;
        if (this.mCreated) {
            setPeekHeight();
        }
    }

    public StrongBottomSheetDialog(@NonNull Context context, int i2, int i3, @StyleRes int i4) {
        this(context, i4);
        this.mPeekHeight = i2;
        this.mMaxHeight = i3;
    }

    private void setMaxHeight() {
        int i2 = this.mMaxHeight;
        if (i2 <= 0) {
            return;
        }
        this.mWindow.setLayout(-1, i2);
        this.mWindow.setGravity(80);
    }

    private void setPeekHeight() {
        if (this.mPeekHeight > 0 && getBottomSheetBehavior() != null) {
            this.mBottomSheetBehavior.setPeekHeight(this.mPeekHeight);
        }
    }

    public StrongBottomSheetDialog(@NonNull Context context, @StyleRes int i2) {
        super(context, i2);
        this.mBottomSheetCallback = new BottomSheetBehavior.BottomSheetCallback() { // from class: com.jbzd.media.movecartoons.ui.dialog.StrongBottomSheetDialog.1
            @Override // com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback
            public void onSlide(@NonNull View view, float f2) {
            }

            @Override // com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback
            public void onStateChanged(@NonNull View view, int i22) {
                if (i22 == 5) {
                    StrongBottomSheetDialog.this.dismiss();
                    BottomSheetBehavior.from(view).setState(4);
                }
            }
        };
        this.mWindow = getWindow();
    }

    public StrongBottomSheetDialog(@NonNull Context context, boolean z, DialogInterface.OnCancelListener onCancelListener) {
        super(context, z, onCancelListener);
        this.mBottomSheetCallback = new BottomSheetBehavior.BottomSheetCallback() { // from class: com.jbzd.media.movecartoons.ui.dialog.StrongBottomSheetDialog.1
            @Override // com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback
            public void onSlide(@NonNull View view, float f2) {
            }

            @Override // com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback
            public void onStateChanged(@NonNull View view, int i22) {
                if (i22 == 5) {
                    StrongBottomSheetDialog.this.dismiss();
                    BottomSheetBehavior.from(view).setState(4);
                }
            }
        };
    }
}
