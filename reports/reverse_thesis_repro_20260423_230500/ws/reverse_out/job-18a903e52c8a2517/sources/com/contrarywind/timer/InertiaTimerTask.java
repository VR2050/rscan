package com.contrarywind.timer;

import com.contrarywind.view.WheelView;
import java.util.TimerTask;

/* JADX INFO: loaded from: classes.dex */
public final class InertiaTimerTask extends TimerTask {
    private float mCurrentVelocityY = 2.1474836E9f;
    private final float mFirstVelocityY;
    private final WheelView mWheelView;

    public InertiaTimerTask(WheelView wheelView, float velocityY) {
        this.mWheelView = wheelView;
        this.mFirstVelocityY = velocityY;
    }

    @Override // java.util.TimerTask, java.lang.Runnable
    public final void run() {
        if (this.mCurrentVelocityY == 2.1474836E9f) {
            if (Math.abs(this.mFirstVelocityY) > 2000.0f) {
                this.mCurrentVelocityY = this.mFirstVelocityY <= 0.0f ? -2000.0f : 2000.0f;
            } else {
                this.mCurrentVelocityY = this.mFirstVelocityY;
            }
        }
        if (Math.abs(this.mCurrentVelocityY) >= 0.0f && Math.abs(this.mCurrentVelocityY) <= 20.0f) {
            this.mWheelView.cancelFuture();
            this.mWheelView.getHandler().sendEmptyMessage(2000);
            return;
        }
        int dy = (int) (this.mCurrentVelocityY / 100.0f);
        WheelView wheelView = this.mWheelView;
        wheelView.setTotalScrollY(wheelView.getTotalScrollY() - dy);
        if (!this.mWheelView.isLoop()) {
            float itemHeight = this.mWheelView.getItemHeight();
            float top = (-this.mWheelView.getInitPosition()) * itemHeight;
            float bottom = ((this.mWheelView.getItemsCount() - 1) - this.mWheelView.getInitPosition()) * itemHeight;
            if (((double) this.mWheelView.getTotalScrollY()) - (((double) itemHeight) * 0.25d) < top) {
                top = this.mWheelView.getTotalScrollY() + dy;
            } else if (((double) this.mWheelView.getTotalScrollY()) + (((double) itemHeight) * 0.25d) > bottom) {
                bottom = this.mWheelView.getTotalScrollY() + dy;
            }
            if (this.mWheelView.getTotalScrollY() <= top) {
                this.mCurrentVelocityY = 40.0f;
                this.mWheelView.setTotalScrollY((int) top);
            } else if (this.mWheelView.getTotalScrollY() >= bottom) {
                this.mWheelView.setTotalScrollY((int) bottom);
                this.mCurrentVelocityY = -40.0f;
            }
        }
        float itemHeight2 = this.mCurrentVelocityY;
        if (itemHeight2 < 0.0f) {
            this.mCurrentVelocityY = itemHeight2 + 20.0f;
        } else {
            this.mCurrentVelocityY = itemHeight2 - 20.0f;
        }
        this.mWheelView.getHandler().sendEmptyMessage(1000);
    }
}
