package com.preview;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Matrix;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import androidx.fragment.app.Fragment;
import com.preview.interfaces.ImageLoader;
import com.preview.interfaces.OnLongClickListener;
import com.preview.photoview.OnFingerUpListener;
import com.preview.photoview.OnViewDragListener;
import com.preview.photoview.PhotoView;
import com.preview.util.Utils;
import com.preview.util.notch.OSUtils;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes2.dex */
public class PhotoPreviewFragment extends Fragment {
    private Context mContext;
    private long mDelayShowProgressTime;
    private boolean mFullScreen;
    private Handler mHandler;
    private int[] mImageLocation;
    private int[] mImageSize;
    private ImageLoader mLoadImage;
    private ProgressBar mLoading;
    private boolean mNeedInAnim;
    private OnExitListener mOnExitListener;
    private OnLongClickListener mOnLongClickListener;
    private PhotoView mPhotoView;
    private int mPosition;
    private Integer mProgressColor;
    private Drawable mProgressDrawable;
    private FrameLayout mRoot;
    private ScheduledFuture<?> mSchedule;
    private ScheduledExecutorService mService;
    private Object mUrl;
    private float mAlpha = 1.0f;
    private int mIntAlpha = 255;
    private final String TAG = PhotoPreviewFragment.class.getSimpleName();

    public interface OnExitListener {
        void onExit();

        void onStart();
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        this.mContext = context;
    }

    @Override // androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (savedInstanceState == null) {
            initData();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        if (savedInstanceState != null) {
            return null;
        }
        View view = inflater.inflate(R.layout.fragment_preview, (ViewGroup) null);
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.attr.root);
        this.mRoot = frameLayout;
        frameLayout.setFocusableInTouchMode(true);
        this.mRoot.requestFocus();
        this.mPhotoView = (PhotoView) view.findViewById(R.attr.photoView);
        this.mLoading = (ProgressBar) view.findViewById(R.attr.loading);
        initEvent();
        onLoadData();
        return view;
    }

    @Override // androidx.fragment.app.Fragment
    public void setUserVisibleHint(boolean isVisibleToUser) {
        PhotoView photoView;
        super.setUserVisibleHint(isVisibleToUser);
        if (!getUserVisibleHint() && (photoView = this.mPhotoView) != null) {
            photoView.setScale(1.0f);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        ScheduledFuture<?> scheduledFuture = this.mSchedule;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        ScheduledExecutorService scheduledExecutorService = this.mService;
        if (scheduledExecutorService != null) {
            scheduledExecutorService.shutdownNow();
        }
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
        }
    }

    private void initData() {
        this.mService = Executors.newScheduledThreadPool(1);
        this.mHandler = new Handler();
    }

    private void initEvent() {
        this.mRoot.setOnKeyListener(new View.OnKeyListener() { // from class: com.preview.PhotoPreviewFragment.1
            @Override // android.view.View.OnKeyListener
            public boolean onKey(View v, int keyCode, KeyEvent event) {
                if (keyCode == 4) {
                    PhotoPreviewFragment.this.exit();
                    return true;
                }
                return false;
            }
        });
        this.mPhotoView.setOnLongClickListener(new View.OnLongClickListener() { // from class: com.preview.PhotoPreviewFragment.2
            @Override // android.view.View.OnLongClickListener
            public boolean onLongClick(View v) {
                if (PhotoPreviewFragment.this.mOnLongClickListener != null) {
                    PhotoPreviewFragment.this.mOnLongClickListener.onLongClick(PhotoPreviewFragment.this.mRoot, PhotoPreviewFragment.this.mUrl, PhotoPreviewFragment.this.mPosition);
                    return true;
                }
                return true;
            }
        });
        this.mPhotoView.getAttacher().setOnFingerUpListener(new OnFingerUpListener() { // from class: com.preview.PhotoPreviewFragment.3
            @Override // com.preview.photoview.OnFingerUpListener
            public void onFingerUp() {
                if (PhotoPreviewFragment.this.mIntAlpha < 150 && PhotoPreviewFragment.this.mOnExitListener != null) {
                    PhotoPreviewFragment.this.exit();
                } else {
                    ValueAnimator va = ValueAnimator.ofFloat(PhotoPreviewFragment.this.mPhotoView.getAlpha(), 1.0f);
                    ValueAnimator bgVa = ValueAnimator.ofInt(PhotoPreviewFragment.this.mIntAlpha, 255);
                    va.setDuration(200L);
                    bgVa.setDuration(200L);
                    va.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.preview.PhotoPreviewFragment.3.1
                        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                        public void onAnimationUpdate(ValueAnimator animation) {
                            PhotoPreviewFragment.this.mPhotoView.setAlpha(((Float) animation.getAnimatedValue()).floatValue());
                        }
                    });
                    bgVa.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.preview.PhotoPreviewFragment.3.2
                        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                        public void onAnimationUpdate(ValueAnimator animation) {
                            PhotoPreviewFragment.this.mRoot.getBackground().setAlpha(((Integer) animation.getAnimatedValue()).intValue());
                        }
                    });
                    va.start();
                    bgVa.start();
                    PhotoPreviewFragment.this.mPhotoView.smoothResetPosition();
                }
                PhotoPreviewFragment.this.mAlpha = 1.0f;
                PhotoPreviewFragment.this.mIntAlpha = 255;
            }
        });
        this.mPhotoView.setOnViewDragListener(new OnViewDragListener() { // from class: com.preview.PhotoPreviewFragment.4
            @Override // com.preview.photoview.OnViewDragListener
            public void onDrag(float dx, float dy) {
                PhotoPreviewFragment.this.mPhotoView.scrollBy((int) (-dx), (int) (-dy));
                float scrollY = PhotoPreviewFragment.this.mPhotoView.getScrollY();
                if (scrollY >= 0.0f) {
                    PhotoPreviewFragment.this.mAlpha = 1.0f;
                    PhotoPreviewFragment.this.mIntAlpha = 255;
                } else {
                    PhotoPreviewFragment.this.mAlpha -= 0.001f * dy;
                    PhotoPreviewFragment photoPreviewFragment = PhotoPreviewFragment.this;
                    photoPreviewFragment.mIntAlpha = (int) (((double) photoPreviewFragment.mIntAlpha) - (((double) dy) * 0.25d));
                }
                if (PhotoPreviewFragment.this.mAlpha > 1.0f) {
                    PhotoPreviewFragment.this.mAlpha = 1.0f;
                } else if (PhotoPreviewFragment.this.mAlpha < 0.0f) {
                    PhotoPreviewFragment.this.mAlpha = 0.0f;
                }
                if (PhotoPreviewFragment.this.mIntAlpha < 0) {
                    PhotoPreviewFragment.this.mIntAlpha = 0;
                } else if (PhotoPreviewFragment.this.mIntAlpha > 255) {
                    PhotoPreviewFragment.this.mIntAlpha = 255;
                }
                PhotoPreviewFragment.this.mRoot.getBackground().setAlpha(PhotoPreviewFragment.this.mIntAlpha);
            }
        });
        this.mPhotoView.setOnClickListener(new View.OnClickListener() { // from class: com.preview.PhotoPreviewFragment.5
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                PhotoPreviewFragment.this.exit();
            }
        });
        this.mRoot.setOnClickListener(new View.OnClickListener() { // from class: com.preview.PhotoPreviewFragment.6
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                PhotoPreviewFragment.this.exit();
            }
        });
    }

    public void onLoadData() {
        this.mAlpha = 1.0f;
        this.mIntAlpha = 255;
        this.mPhotoView.setImageDrawable(null);
        this.mLoadImage.onLoadImage(this.mPosition, this.mUrl, this.mPhotoView);
        checkLoadResult();
        this.mRoot.getBackground().setAlpha(this.mIntAlpha);
        if (this.mNeedInAnim) {
            this.mNeedInAnim = false;
            this.mPhotoView.post(new Runnable() { // from class: com.preview.PhotoPreviewFragment.7
                @Override // java.lang.Runnable
                public void run() {
                    PhotoPreviewFragment.this.mPhotoView.setVisibility(0);
                    ObjectAnimator scaleXOa = ObjectAnimator.ofFloat(PhotoPreviewFragment.this.mPhotoView, "scaleX", (PhotoPreviewFragment.this.mImageSize[0] * 1.0f) / PhotoPreviewFragment.this.mPhotoView.getWidth(), 1.0f);
                    ObjectAnimator scaleYOa = ObjectAnimator.ofFloat(PhotoPreviewFragment.this.mPhotoView, "scaleY", (PhotoPreviewFragment.this.mImageSize[1] * 1.0f) / PhotoPreviewFragment.this.mPhotoView.getHeight(), 1.0f);
                    ObjectAnimator xOa = ObjectAnimator.ofFloat(PhotoPreviewFragment.this.mPhotoView, "translationX", PhotoPreviewFragment.this.mImageLocation[0] - (PhotoPreviewFragment.this.mPhotoView.getWidth() / 2.0f), 0.0f);
                    ObjectAnimator yOa = ObjectAnimator.ofFloat(PhotoPreviewFragment.this.mPhotoView, "translationY", PhotoPreviewFragment.this.getTranslationY(), 0.0f);
                    AnimatorSet set = new AnimatorSet();
                    set.setDuration(250L);
                    set.playTogether(scaleXOa, scaleYOa, xOa, yOa);
                    set.start();
                }
            });
        } else {
            this.mPhotoView.setVisibility(0);
        }
    }

    private void checkLoadResult() {
        Integer num;
        if (this.mDelayShowProgressTime < 0) {
            this.mLoading.setVisibility(8);
            return;
        }
        Drawable drawable = this.mProgressDrawable;
        if (drawable != null) {
            this.mLoading.setIndeterminateDrawable(drawable);
        }
        if (Build.VERSION.SDK_INT >= 21 && (num = this.mProgressColor) != null) {
            this.mLoading.setIndeterminateTintList(ColorStateList.valueOf(num.intValue()));
        }
        this.mLoading.setVisibility(this.mDelayShowProgressTime == 0 ? 0 : 8);
        ScheduledExecutorService scheduledExecutorService = this.mService;
        Runnable runnable = new Runnable() { // from class: com.preview.PhotoPreviewFragment.8
            @Override // java.lang.Runnable
            public void run() {
                if (PhotoPreviewFragment.this.mPhotoView.getDrawable() != null) {
                    PhotoPreviewFragment.this.mHandler.post(new Runnable() { // from class: com.preview.PhotoPreviewFragment.8.1
                        @Override // java.lang.Runnable
                        public void run() {
                            PhotoPreviewFragment.this.mLoading.setVisibility(8);
                        }
                    });
                    PhotoPreviewFragment.this.mSchedule.cancel(true);
                } else if (PhotoPreviewFragment.this.mLoading.getVisibility() == 8) {
                    PhotoPreviewFragment.this.mHandler.post(new Runnable() { // from class: com.preview.PhotoPreviewFragment.8.2
                        @Override // java.lang.Runnable
                        public void run() {
                            PhotoPreviewFragment.this.mLoading.setVisibility(0);
                        }
                    });
                }
            }
        };
        long j = this.mDelayShowProgressTime;
        if (j == 0) {
            j = 100;
        }
        this.mSchedule = scheduledExecutorService.scheduleWithFixedDelay(runnable, j, 100L, TimeUnit.MILLISECONDS);
    }

    public void exit() {
        Matrix m = new Matrix();
        m.postScale(this.mImageSize[0] / this.mPhotoView.getWidth(), this.mImageSize[1] / this.mPhotoView.getHeight());
        PhotoView photoView = this.mPhotoView;
        ObjectAnimator scaleOa = ObjectAnimator.ofFloat(photoView, "scale", photoView.getAttacher().getScale(m));
        ObjectAnimator xOa = ObjectAnimator.ofFloat(this.mPhotoView, "translationX", (this.mImageLocation[0] - (r3.getWidth() / 2.0f)) + this.mPhotoView.getScrollX());
        ObjectAnimator yOa = ObjectAnimator.ofFloat(this.mPhotoView, "translationY", getTranslationY());
        AnimatorSet set = new AnimatorSet();
        set.setDuration(250L);
        set.playTogether(scaleOa, xOa, yOa);
        OnExitListener onExitListener = this.mOnExitListener;
        if (onExitListener != null) {
            onExitListener.onStart();
        }
        set.start();
        this.mHandler.postDelayed(new Runnable() { // from class: com.preview.PhotoPreviewFragment.9
            @Override // java.lang.Runnable
            public void run() {
                if (PhotoPreviewFragment.this.mOnExitListener != null) {
                    PhotoPreviewFragment.this.mOnExitListener.onExit();
                }
            }
        }, 250L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public float getTranslationY() {
        float translationY = (this.mImageLocation[1] - (this.mPhotoView.getHeight() / 2.0f)) + this.mPhotoView.getScrollY();
        if (OSUtils.isVivo() || !this.mFullScreen) {
            return translationY - Utils.getStatusBarHeight(this.mContext);
        }
        return translationY;
    }

    public void setData(ImageLoader loadImage, int position, Object url, int[] imageSize, int[] imageLocation, boolean needInAnim, long delayShowProgressTime, Integer progressColor, Drawable progressDrawable, boolean fullScreen) {
        this.mLoadImage = loadImage;
        this.mUrl = url;
        this.mImageSize = imageSize;
        this.mImageLocation = imageLocation;
        this.mNeedInAnim = needInAnim;
        this.mPosition = position;
        this.mDelayShowProgressTime = delayShowProgressTime;
        this.mProgressColor = progressColor;
        this.mProgressDrawable = progressDrawable;
        this.mFullScreen = fullScreen;
    }

    public void setOnExitListener(OnExitListener onExitListener) {
        this.mOnExitListener = onExitListener;
    }

    public void setOnLongClickListener(OnLongClickListener onLongClickListener) {
        this.mOnLongClickListener = onLongClickListener;
    }
}
