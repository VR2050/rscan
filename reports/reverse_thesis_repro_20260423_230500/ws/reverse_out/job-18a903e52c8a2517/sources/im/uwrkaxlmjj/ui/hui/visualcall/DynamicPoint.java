package im.uwrkaxlmjj.ui.hui.visualcall;

import android.widget.TextView;
import java.util.Timer;
import java.util.TimerTask;

/* JADX INFO: loaded from: classes5.dex */
public class DynamicPoint {
    private int iCount = 0;
    private Timer timer = new Timer();
    private TimerTask timerTask;

    static /* synthetic */ int access$008(DynamicPoint x0) {
        int i = x0.iCount;
        x0.iCount = i + 1;
        return i;
    }

    public void animForWaitting(String strText, TextView textView) {
        this.iCount = 0;
        TimerTask timerTask = this.timerTask;
        if (timerTask != null) {
            timerTask.cancel();
        }
        AnonymousClass1 anonymousClass1 = new AnonymousClass1(textView, strText);
        this.timerTask = anonymousClass1;
        this.timer.schedule(anonymousClass1, 0L, 1000L);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.visualcall.DynamicPoint$1, reason: invalid class name */
    class AnonymousClass1 extends TimerTask {
        final /* synthetic */ String val$strText;
        final /* synthetic */ TextView val$textView;

        AnonymousClass1(TextView textView, String str) {
            this.val$textView = textView;
            this.val$strText = str;
        }

        @Override // java.util.TimerTask, java.lang.Runnable
        public void run() {
            final TextView textView = this.val$textView;
            final String str = this.val$strText;
            ThreadUtils.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$DynamicPoint$1$DT1FJ4-IRe84_LEcNp2uDjhajqs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$run$0$DynamicPoint$1(textView, str);
                }
            });
        }

        public /* synthetic */ void lambda$run$0$DynamicPoint$1(TextView textView, String strText) {
            if (DynamicPoint.this.iCount % 4 != 0) {
                if (DynamicPoint.this.iCount % 4 != 1) {
                    if (DynamicPoint.this.iCount % 4 != 2) {
                        if (DynamicPoint.this.iCount % 4 == 3) {
                            textView.setText(strText + "...");
                        }
                    } else {
                        textView.setText(strText + "..");
                    }
                } else {
                    textView.setText(strText + ".");
                }
            } else {
                textView.setText(strText);
            }
            DynamicPoint.access$008(DynamicPoint.this);
        }
    }

    public void release() {
        this.timer.cancel();
        this.timer.purge();
    }

    public void cancel() {
        TimerTask timerTask = this.timerTask;
        if (timerTask != null) {
            timerTask.cancel();
        }
    }
}
