package im.uwrkaxlmjj.ui.hui.packet.pop;

import android.widget.ImageView;

/* JADX INFO: loaded from: classes5.dex */
public class FrameAnimation {
    private static final int SELECTED_A = 1;
    private static final int SELECTED_B = 2;
    private static final int SELECTED_C = 3;
    private static final int SELECTED_D = 4;
    private AnimationListener mAnimationListener;
    private int mCurrentFrame;
    private int mCurrentSelect;
    private int mDelay;
    private int mDuration;
    private int[] mDurations;
    private int[] mFrameRess;
    private ImageView mImageView;
    private boolean mIsRepeat;
    private int mLastFrame;
    private boolean mNext;
    private boolean mPause;

    public interface AnimationListener {
        void onAnimationEnd();

        void onAnimationPause();

        void onAnimationRepeat();

        void onAnimationStart();
    }

    public FrameAnimation(ImageView iv, int[] frameRes, int duration, boolean isRepeat) {
        this.mImageView = iv;
        this.mFrameRess = frameRes;
        this.mDuration = duration;
        this.mLastFrame = frameRes.length - 1;
        this.mIsRepeat = isRepeat;
        play(0);
    }

    public FrameAnimation(ImageView iv, int[] frameRess, int[] durations, boolean isRepeat) {
        this.mImageView = iv;
        this.mFrameRess = frameRess;
        this.mDurations = durations;
        this.mLastFrame = frameRess.length - 1;
        this.mIsRepeat = isRepeat;
        playByDurations(0);
    }

    public FrameAnimation(ImageView iv, int[] frameRess, int duration, int delay) {
        this.mImageView = iv;
        this.mFrameRess = frameRess;
        this.mDuration = duration;
        this.mDelay = delay;
        this.mLastFrame = frameRess.length - 1;
        playAndDelay(0);
    }

    public FrameAnimation(ImageView iv, int[] frameRess, int[] durations, int delay) {
        this.mImageView = iv;
        this.mFrameRess = frameRess;
        this.mDurations = durations;
        this.mDelay = delay;
        this.mLastFrame = frameRess.length - 1;
        playByDurationsAndDelay(0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void playByDurationsAndDelay(final int i) {
        int i2;
        ImageView imageView = this.mImageView;
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation.1
            @Override // java.lang.Runnable
            public void run() {
                if (FrameAnimation.this.mPause) {
                    FrameAnimation.this.mCurrentSelect = 1;
                    FrameAnimation.this.mCurrentFrame = i;
                    return;
                }
                if (i == 0 && FrameAnimation.this.mAnimationListener != null) {
                    FrameAnimation.this.mAnimationListener.onAnimationStart();
                }
                FrameAnimation.this.mImageView.setBackgroundResource(FrameAnimation.this.mFrameRess[i]);
                if (i == FrameAnimation.this.mLastFrame) {
                    if (FrameAnimation.this.mAnimationListener != null) {
                        FrameAnimation.this.mAnimationListener.onAnimationRepeat();
                    }
                    FrameAnimation.this.mNext = true;
                    FrameAnimation.this.playByDurationsAndDelay(0);
                    return;
                }
                FrameAnimation.this.playByDurationsAndDelay(i + 1);
            }
        };
        if (!this.mNext || (i2 = this.mDelay) <= 0) {
            i2 = this.mDurations[i];
        }
        imageView.postDelayed(runnable, i2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void playAndDelay(final int i) {
        int i2;
        ImageView imageView = this.mImageView;
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation.2
            @Override // java.lang.Runnable
            public void run() {
                if (FrameAnimation.this.mPause) {
                    if (FrameAnimation.this.mPause) {
                        FrameAnimation.this.mCurrentSelect = 2;
                        FrameAnimation.this.mCurrentFrame = i;
                        return;
                    }
                    return;
                }
                FrameAnimation.this.mNext = false;
                if (i == 0 && FrameAnimation.this.mAnimationListener != null) {
                    FrameAnimation.this.mAnimationListener.onAnimationStart();
                }
                FrameAnimation.this.mImageView.setBackgroundResource(FrameAnimation.this.mFrameRess[i]);
                if (i == FrameAnimation.this.mLastFrame) {
                    if (FrameAnimation.this.mAnimationListener != null) {
                        FrameAnimation.this.mAnimationListener.onAnimationRepeat();
                    }
                    FrameAnimation.this.mNext = true;
                    FrameAnimation.this.playAndDelay(0);
                    return;
                }
                FrameAnimation.this.playAndDelay(i + 1);
            }
        };
        if (!this.mNext || (i2 = this.mDelay) <= 0) {
            i2 = this.mDuration;
        }
        imageView.postDelayed(runnable, i2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void playByDurations(final int i) {
        this.mImageView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation.3
            @Override // java.lang.Runnable
            public void run() {
                if (FrameAnimation.this.mPause) {
                    if (FrameAnimation.this.mPause) {
                        FrameAnimation.this.mCurrentSelect = 3;
                        FrameAnimation.this.mCurrentFrame = i;
                        if (FrameAnimation.this.mAnimationListener != null) {
                            FrameAnimation.this.mAnimationListener.onAnimationPause();
                            return;
                        }
                        return;
                    }
                    return;
                }
                if (i == 0 && FrameAnimation.this.mAnimationListener != null) {
                    FrameAnimation.this.mAnimationListener.onAnimationStart();
                }
                FrameAnimation.this.mImageView.setBackgroundResource(FrameAnimation.this.mFrameRess[i]);
                if (i == FrameAnimation.this.mLastFrame) {
                    if (FrameAnimation.this.mIsRepeat) {
                        if (FrameAnimation.this.mAnimationListener != null) {
                            FrameAnimation.this.mAnimationListener.onAnimationRepeat();
                        }
                        FrameAnimation.this.playByDurations(0);
                        return;
                    } else {
                        if (FrameAnimation.this.mAnimationListener != null) {
                            FrameAnimation.this.mAnimationListener.onAnimationEnd();
                            return;
                        }
                        return;
                    }
                }
                FrameAnimation.this.playByDurations(i + 1);
            }
        }, this.mDurations[i]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void play(final int i) {
        this.mImageView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.pop.FrameAnimation.4
            @Override // java.lang.Runnable
            public void run() {
                if (FrameAnimation.this.mPause) {
                    if (FrameAnimation.this.mPause) {
                        FrameAnimation.this.mCurrentSelect = 4;
                        FrameAnimation.this.mCurrentFrame = i;
                        if (FrameAnimation.this.mAnimationListener != null) {
                            FrameAnimation.this.mAnimationListener.onAnimationPause();
                            return;
                        }
                        return;
                    }
                    return;
                }
                if (i == 0 && FrameAnimation.this.mAnimationListener != null) {
                    FrameAnimation.this.mAnimationListener.onAnimationStart();
                }
                FrameAnimation.this.mImageView.setBackgroundResource(FrameAnimation.this.mFrameRess[i]);
                if (i == FrameAnimation.this.mLastFrame) {
                    if (FrameAnimation.this.mIsRepeat) {
                        if (FrameAnimation.this.mAnimationListener != null) {
                            FrameAnimation.this.mAnimationListener.onAnimationRepeat();
                        }
                        FrameAnimation.this.play(0);
                        return;
                    } else {
                        if (FrameAnimation.this.mAnimationListener != null) {
                            FrameAnimation.this.mAnimationListener.onAnimationEnd();
                            return;
                        }
                        return;
                    }
                }
                FrameAnimation.this.play(i + 1);
            }
        }, this.mDuration);
    }

    public void setAnimationListener(AnimationListener listener) {
        this.mAnimationListener = listener;
    }

    public void release() {
        pauseAnimation();
    }

    public void pauseAnimation() {
        this.mPause = true;
    }

    public boolean isPause() {
        return this.mPause;
    }

    public void restartAnimation() {
        if (this.mPause) {
            this.mPause = false;
            int i = this.mCurrentSelect;
            if (i == 1) {
                playByDurationsAndDelay(this.mCurrentFrame);
                return;
            }
            if (i == 2) {
                playAndDelay(this.mCurrentFrame);
            } else if (i == 3) {
                playByDurations(this.mCurrentFrame);
            } else if (i == 4) {
                play(this.mCurrentFrame);
            }
        }
    }
}
