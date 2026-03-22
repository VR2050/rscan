package com.luck.picture.lib.camera.view;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.motion.widget.Key;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.camera.listener.CaptureListener;
import com.luck.picture.lib.camera.listener.ClickListener;
import com.luck.picture.lib.camera.listener.TypeListener;
import com.luck.picture.lib.camera.view.CaptureLayout;

/* loaded from: classes2.dex */
public class CaptureLayout extends FrameLayout {
    private TypeButton btn_cancel;
    private CaptureButton btn_capture;
    private TypeButton btn_confirm;
    private ReturnButton btn_return;
    private int button_size;
    private CaptureListener captureListener;
    private int iconLeft;
    private int iconRight;
    private ImageView iv_custom_left;
    private ImageView iv_custom_right;
    private int layout_height;
    private int layout_width;
    private ClickListener leftClickListener;
    private ClickListener rightClickListener;
    private TextView txt_tip;
    private TypeListener typeListener;

    public CaptureLayout(Context context) {
        this(context, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getCaptureTip() {
        int buttonFeatures = this.btn_capture.getButtonFeatures();
        return buttonFeatures != 257 ? buttonFeatures != 258 ? getContext().getString(C3979R.string.picture_photo_camera) : getContext().getString(C3979R.string.picture_photo_recording) : getContext().getString(C3979R.string.picture_photo_pictures);
    }

    private void initView() {
        setWillNotDraw(false);
        this.btn_capture = new CaptureButton(getContext(), this.button_size);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
        layoutParams.gravity = 17;
        this.btn_capture.setLayoutParams(layoutParams);
        this.btn_capture.setCaptureListener(new CaptureListener() { // from class: com.luck.picture.lib.camera.view.CaptureLayout.2
            @Override // com.luck.picture.lib.camera.listener.CaptureListener
            public void recordEnd(long j2) {
                if (CaptureLayout.this.captureListener != null) {
                    CaptureLayout.this.captureListener.recordEnd(j2);
                }
                CaptureLayout.this.startTypeBtnAnimator();
            }

            @Override // com.luck.picture.lib.camera.listener.CaptureListener
            public void recordError() {
                if (CaptureLayout.this.captureListener != null) {
                    CaptureLayout.this.captureListener.recordError();
                }
            }

            @Override // com.luck.picture.lib.camera.listener.CaptureListener
            public void recordShort(long j2) {
                if (CaptureLayout.this.captureListener != null) {
                    CaptureLayout.this.captureListener.recordShort(j2);
                }
            }

            @Override // com.luck.picture.lib.camera.listener.CaptureListener
            public void recordStart() {
                if (CaptureLayout.this.captureListener != null) {
                    CaptureLayout.this.captureListener.recordStart();
                }
                CaptureLayout.this.startAlphaAnimation();
            }

            @Override // com.luck.picture.lib.camera.listener.CaptureListener
            public void recordZoom(float f2) {
                if (CaptureLayout.this.captureListener != null) {
                    CaptureLayout.this.captureListener.recordZoom(f2);
                }
            }

            @Override // com.luck.picture.lib.camera.listener.CaptureListener
            public void takePictures() {
                if (CaptureLayout.this.captureListener != null) {
                    CaptureLayout.this.captureListener.takePictures();
                }
                CaptureLayout.this.startAlphaAnimation();
            }
        });
        this.btn_cancel = new TypeButton(getContext(), 1, this.button_size);
        FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(-1, -1);
        layoutParams2.gravity = 16;
        layoutParams2.setMargins((this.layout_width / 4) - (this.button_size / 2), 0, 0, 0);
        this.btn_cancel.setLayoutParams(layoutParams2);
        this.btn_cancel.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.i0.f.f
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                CaptureLayout.this.m4548a(view);
            }
        });
        this.btn_confirm = new TypeButton(getContext(), 2, this.button_size);
        FrameLayout.LayoutParams layoutParams3 = new FrameLayout.LayoutParams(-1, -1);
        layoutParams3.gravity = 21;
        layoutParams3.setMargins(0, 0, (this.layout_width / 4) - (this.button_size / 2), 0);
        this.btn_confirm.setLayoutParams(layoutParams3);
        this.btn_confirm.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.i0.f.d
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                CaptureLayout.this.m4549b(view);
            }
        });
        this.btn_return = new ReturnButton(getContext(), (int) (this.button_size / 2.5f));
        FrameLayout.LayoutParams layoutParams4 = new FrameLayout.LayoutParams(-2, -2);
        layoutParams4.gravity = 16;
        layoutParams4.setMargins(this.layout_width / 6, 0, 0, 0);
        this.btn_return.setLayoutParams(layoutParams4);
        this.btn_return.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.i0.f.h
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                CaptureLayout.this.m4550c(view);
            }
        });
        this.iv_custom_left = new ImageView(getContext());
        int i2 = this.button_size;
        FrameLayout.LayoutParams layoutParams5 = new FrameLayout.LayoutParams((int) (i2 / 2.5f), (int) (i2 / 2.5f));
        layoutParams5.gravity = 16;
        layoutParams5.setMargins(this.layout_width / 6, 0, 0, 0);
        this.iv_custom_left.setLayoutParams(layoutParams5);
        this.iv_custom_left.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.i0.f.g
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                CaptureLayout.this.m4551d(view);
            }
        });
        this.iv_custom_right = new ImageView(getContext());
        int i3 = this.button_size;
        FrameLayout.LayoutParams layoutParams6 = new FrameLayout.LayoutParams((int) (i3 / 2.5f), (int) (i3 / 2.5f));
        layoutParams6.gravity = 21;
        layoutParams6.setMargins(0, 0, this.layout_width / 6, 0);
        this.iv_custom_right.setLayoutParams(layoutParams6);
        this.iv_custom_right.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.i0.f.e
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                CaptureLayout.this.m4552e(view);
            }
        });
        this.txt_tip = new TextView(getContext());
        FrameLayout.LayoutParams layoutParams7 = new FrameLayout.LayoutParams(-1, -2);
        layoutParams7.gravity = 1;
        layoutParams7.setMargins(0, 0, 0, 0);
        this.txt_tip.setText(getCaptureTip());
        this.txt_tip.setTextColor(-1);
        this.txt_tip.setGravity(17);
        this.txt_tip.setLayoutParams(layoutParams7);
        addView(this.btn_capture);
        addView(this.btn_cancel);
        addView(this.btn_confirm);
        addView(this.btn_return);
        addView(this.iv_custom_left);
        addView(this.iv_custom_right);
        addView(this.txt_tip);
    }

    /* renamed from: a */
    public /* synthetic */ void m4548a(View view) {
        TypeListener typeListener = this.typeListener;
        if (typeListener != null) {
            typeListener.cancel();
        }
    }

    /* renamed from: b */
    public /* synthetic */ void m4549b(View view) {
        TypeListener typeListener = this.typeListener;
        if (typeListener != null) {
            typeListener.confirm();
        }
    }

    /* renamed from: c */
    public /* synthetic */ void m4550c(View view) {
        ClickListener clickListener = this.leftClickListener;
        if (clickListener != null) {
            clickListener.onClick();
        }
    }

    /* renamed from: d */
    public /* synthetic */ void m4551d(View view) {
        ClickListener clickListener = this.leftClickListener;
        if (clickListener != null) {
            clickListener.onClick();
        }
    }

    /* renamed from: e */
    public /* synthetic */ void m4552e(View view) {
        ClickListener clickListener = this.rightClickListener;
        if (clickListener != null) {
            clickListener.onClick();
        }
    }

    public void initEvent() {
        this.iv_custom_right.setVisibility(8);
        this.btn_cancel.setVisibility(8);
        this.btn_confirm.setVisibility(8);
    }

    @Override // android.widget.FrameLayout, android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        setMeasuredDimension(this.layout_width, this.layout_height);
    }

    public void resetCaptureLayout() {
        this.btn_capture.resetState();
        this.btn_cancel.setVisibility(8);
        this.btn_confirm.setVisibility(8);
        this.btn_capture.setVisibility(0);
        this.txt_tip.setText(getCaptureTip());
        this.txt_tip.setVisibility(0);
        if (this.iconLeft != 0) {
            this.iv_custom_left.setVisibility(0);
        } else {
            this.btn_return.setVisibility(0);
        }
        if (this.iconRight != 0) {
            this.iv_custom_right.setVisibility(0);
        }
    }

    public void setButtonFeatures(int i2) {
        this.btn_capture.setButtonFeatures(i2);
        this.txt_tip.setText(getCaptureTip());
    }

    public void setCaptureListener(CaptureListener captureListener) {
        this.captureListener = captureListener;
    }

    public void setDuration(int i2) {
        this.btn_capture.setDuration(i2);
    }

    public void setIconSrc(int i2, int i3) {
        this.iconLeft = i2;
        this.iconRight = i3;
        if (i2 != 0) {
            this.iv_custom_left.setImageResource(i2);
            this.iv_custom_left.setVisibility(0);
            this.btn_return.setVisibility(8);
        } else {
            this.iv_custom_left.setVisibility(8);
            this.btn_return.setVisibility(0);
        }
        if (this.iconRight == 0) {
            this.iv_custom_right.setVisibility(8);
        } else {
            this.iv_custom_right.setImageResource(i3);
            this.iv_custom_right.setVisibility(0);
        }
    }

    public void setLeftClickListener(ClickListener clickListener) {
        this.leftClickListener = clickListener;
    }

    public void setMinDuration(int i2) {
        this.btn_capture.setMinDuration(i2);
    }

    public void setRightClickListener(ClickListener clickListener) {
        this.rightClickListener = clickListener;
    }

    public void setTextWithAnimation(String str) {
        this.txt_tip.setText(str);
        ObjectAnimator ofFloat = ObjectAnimator.ofFloat(this.txt_tip, Key.ALPHA, 0.0f, 1.0f, 1.0f, 0.0f);
        ofFloat.addListener(new AnimatorListenerAdapter() { // from class: com.luck.picture.lib.camera.view.CaptureLayout.3
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                super.onAnimationEnd(animator);
                CaptureLayout.this.txt_tip.setText(CaptureLayout.this.getCaptureTip());
                CaptureLayout.this.txt_tip.setAlpha(1.0f);
            }
        });
        ofFloat.setDuration(2500L);
        ofFloat.start();
    }

    public void setTip(String str) {
        this.txt_tip.setText(str);
    }

    public void setTypeListener(TypeListener typeListener) {
        this.typeListener = typeListener;
    }

    public void showTip() {
        this.txt_tip.setVisibility(0);
    }

    public void startAlphaAnimation() {
        this.txt_tip.setVisibility(4);
    }

    public void startTypeBtnAnimator() {
        if (this.iconLeft != 0) {
            this.iv_custom_left.setVisibility(8);
        } else {
            this.btn_return.setVisibility(8);
        }
        if (this.iconRight != 0) {
            this.iv_custom_right.setVisibility(8);
        }
        this.btn_capture.setVisibility(8);
        this.btn_cancel.setVisibility(0);
        this.btn_confirm.setVisibility(0);
        this.btn_cancel.setClickable(false);
        this.btn_confirm.setClickable(false);
        this.iv_custom_left.setVisibility(8);
        ObjectAnimator ofFloat = ObjectAnimator.ofFloat(this.btn_cancel, Key.TRANSLATION_X, this.layout_width / 4, 0.0f);
        ObjectAnimator ofFloat2 = ObjectAnimator.ofFloat(this.btn_confirm, Key.TRANSLATION_X, (-this.layout_width) / 4, 0.0f);
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ofFloat, ofFloat2);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: com.luck.picture.lib.camera.view.CaptureLayout.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                super.onAnimationEnd(animator);
                CaptureLayout.this.btn_cancel.setClickable(true);
                CaptureLayout.this.btn_confirm.setClickable(true);
            }
        });
        animatorSet.setDuration(500L);
        animatorSet.start();
    }

    public CaptureLayout(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public CaptureLayout(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.iconLeft = 0;
        this.iconRight = 0;
        WindowManager windowManager = (WindowManager) context.getSystemService("window");
        DisplayMetrics displayMetrics = new DisplayMetrics();
        windowManager.getDefaultDisplay().getMetrics(displayMetrics);
        if (getResources().getConfiguration().orientation == 1) {
            this.layout_width = displayMetrics.widthPixels;
        } else {
            this.layout_width = displayMetrics.widthPixels / 2;
        }
        int i3 = (int) (this.layout_width / 4.5f);
        this.button_size = i3;
        this.layout_height = ((i3 / 5) * 2) + i3 + 100;
        initView();
        initEvent();
    }
}
