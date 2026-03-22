package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import java.lang.ref.SoftReference;

/* loaded from: classes2.dex */
public class MarqueeRecyclerView extends RecyclerView {
    public AutoPollTask autoPollTask;
    private boolean canRun;
    private boolean running;
    public boolean scrollVertical;
    public long speed;

    public static class AutoPollTask implements Runnable {
        private final SoftReference<MarqueeRecyclerView> mReference;

        public AutoPollTask(MarqueeRecyclerView marqueeRecyclerView) {
            this.mReference = new SoftReference<>(marqueeRecyclerView);
        }

        @Override // java.lang.Runnable
        public void run() {
            MarqueeRecyclerView marqueeRecyclerView = this.mReference.get();
            if (marqueeRecyclerView != null && marqueeRecyclerView.running && marqueeRecyclerView.canRun) {
                if (marqueeRecyclerView.scrollVertical) {
                    marqueeRecyclerView.scrollBy(0, Integer.parseInt(String.valueOf(marqueeRecyclerView.speed)));
                } else {
                    marqueeRecyclerView.scrollBy(Integer.parseInt(String.valueOf(marqueeRecyclerView.speed)), 0);
                }
                marqueeRecyclerView.postDelayed(marqueeRecyclerView.autoPollTask, marqueeRecyclerView.speed);
            }
        }
    }

    public MarqueeRecyclerView(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.speed = 4L;
        this.scrollVertical = true;
        this.canRun = false;
    }

    public long getSpeed() {
        return this.speed;
    }

    public boolean isRunning() {
        return this.running;
    }

    public boolean isScrollVertical() {
        return this.scrollVertical;
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        int action = motionEvent.getAction();
        if (action != 0) {
            if ((action == 1 || action == 3 || action == 4) && this.canRun) {
                start();
            }
        } else if (this.running) {
            stop();
        }
        return super.onTouchEvent(motionEvent);
    }

    public void setAutoRun(boolean z) {
        this.canRun = z;
    }

    public void setScrollVertical(boolean z) {
        this.scrollVertical = z;
    }

    public void setSpeed(long j2) {
        this.speed = j2;
    }

    public void start() {
        if (this.running) {
            stop();
        }
        if (this.canRun) {
            if (this.autoPollTask == null) {
                this.autoPollTask = new AutoPollTask(this);
            }
            this.running = true;
            postDelayed(this.autoPollTask, this.speed);
        }
    }

    public void stop() {
        this.running = false;
        removeCallbacks(this.autoPollTask);
    }
}
