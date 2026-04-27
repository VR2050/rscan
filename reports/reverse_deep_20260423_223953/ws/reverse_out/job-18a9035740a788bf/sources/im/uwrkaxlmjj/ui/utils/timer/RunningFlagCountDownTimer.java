package im.uwrkaxlmjj.ui.utils.timer;

import android.os.CountDownTimer;

/* JADX INFO: loaded from: classes5.dex */
public class RunningFlagCountDownTimer extends CountDownTimer {
    private long currentUntilFinishedMills;
    private boolean isRunning;

    public RunningFlagCountDownTimer(long millisInFuture, long countDownInterval) {
        super(millisInFuture, countDownInterval);
    }

    public void startInternal() {
        this.isRunning = true;
        start();
    }

    public void cancelInternal() {
        this.isRunning = false;
        try {
            cancel();
        } catch (Exception e) {
        }
    }

    @Override // android.os.CountDownTimer
    public void onTick(long millisUntilFinished) {
        this.isRunning = true;
        this.currentUntilFinishedMills = millisUntilFinished;
    }

    @Override // android.os.CountDownTimer
    public void onFinish() {
        this.isRunning = false;
    }

    public boolean isRunning() {
        return this.isRunning;
    }

    public long getCurrentUntilFinishedMills() {
        return this.currentUntilFinishedMills;
    }
}
