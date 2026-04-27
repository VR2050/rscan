package im.uwrkaxlmjj.ui.components;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.RectF;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class PlayingGameDrawable extends StatusDrawable {
    private float progress;
    private boolean isChat = false;
    private Paint paint = new Paint(1);
    private int currentAccount = UserConfig.selectedAccount;
    private long lastUpdateTime = 0;
    private boolean started = false;
    private RectF rect = new RectF();

    @Override // im.uwrkaxlmjj.ui.components.StatusDrawable
    public void setIsChat(boolean value) {
        this.isChat = value;
    }

    private void update() {
        long newTime = System.currentTimeMillis();
        long dt = newTime - this.lastUpdateTime;
        this.lastUpdateTime = newTime;
        if (dt > 16) {
            dt = 16;
        }
        if (this.progress >= 1.0f) {
            this.progress = 0.0f;
        }
        float f = this.progress + (dt / 300.0f);
        this.progress = f;
        if (f > 1.0f) {
            this.progress = 1.0f;
        }
        invalidateSelf();
    }

    @Override // im.uwrkaxlmjj.ui.components.StatusDrawable
    public void start() {
        this.lastUpdateTime = System.currentTimeMillis();
        this.started = true;
        invalidateSelf();
    }

    @Override // im.uwrkaxlmjj.ui.components.StatusDrawable
    public void stop() {
        this.progress = 0.0f;
        this.started = false;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        int rad;
        int size = AndroidUtilities.dp(10.0f);
        int y = getBounds().top + ((getIntrinsicHeight() - size) / 2);
        int y2 = this.isChat ? y : y + AndroidUtilities.dp(1.0f);
        this.paint.setColor(Theme.getColor(Theme.key_chat_status));
        this.rect.set(0.0f, y2, size, y2 + size);
        float f = this.progress;
        if (f < 0.5f) {
            rad = (int) ((1.0f - (f / 0.5f)) * 35.0f);
        } else {
            rad = (int) (((f - 0.5f) * 35.0f) / 0.5f);
        }
        for (int a = 0; a < 3; a++) {
            float fDp = (AndroidUtilities.dp(5.0f) * a) + AndroidUtilities.dp(9.2f);
            float fDp2 = AndroidUtilities.dp(5.0f);
            float f2 = this.progress;
            float x = fDp - (fDp2 * f2);
            if (a == 2) {
                this.paint.setAlpha(Math.min(255, (int) ((f2 * 255.0f) / 0.5f)));
            } else if (a != 0) {
                this.paint.setAlpha(255);
            } else if (f2 > 0.5f) {
                this.paint.setAlpha((int) ((1.0f - ((f2 - 0.5f) / 0.5f)) * 255.0f));
            } else {
                this.paint.setAlpha(255);
            }
            canvas.drawCircle(x, (size / 2) + y2, AndroidUtilities.dp(1.2f), this.paint);
        }
        this.paint.setAlpha(255);
        canvas.drawArc(this.rect, rad, 360 - (rad * 2), true, this.paint);
        this.paint.setColor(Theme.getColor(Theme.key_actionBarDefault));
        canvas.drawCircle(AndroidUtilities.dp(4.0f), ((size / 2) + y2) - AndroidUtilities.dp(2.0f), AndroidUtilities.dp(1.0f), this.paint);
        checkUpdate();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkUpdate() {
        if (this.started) {
            if (!NotificationCenter.getInstance(this.currentAccount).isAnimationInProgress()) {
                update();
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PlayingGameDrawable$BEVXsB9Xoc0EVl4C4AyzfRwMLYI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.checkUpdate();
                    }
                }, 100L);
            }
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter cf) {
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -2;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return AndroidUtilities.dp(20.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return AndroidUtilities.dp(18.0f);
    }
}
