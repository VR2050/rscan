package im.uwrkaxlmjj.ui.components;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class RoundVideoPlayingDrawable extends Drawable {
    private View parentView;
    private long lastUpdateTime = 0;
    private boolean started = false;
    private Paint paint = new Paint(1);
    private float progress1 = 0.47f;
    private float progress2 = 0.0f;
    private float progress3 = 0.32f;
    private int progress1Direction = 1;
    private int progress2Direction = 1;
    private int progress3Direction = 1;

    public RoundVideoPlayingDrawable(View view) {
        this.parentView = view;
    }

    private void update() {
        long newTime = System.currentTimeMillis();
        long dt = newTime - this.lastUpdateTime;
        this.lastUpdateTime = newTime;
        if (dt > 50) {
            dt = 50;
        }
        float f = this.progress1 + ((dt / 300.0f) * this.progress1Direction);
        this.progress1 = f;
        if (f > 1.0f) {
            this.progress1Direction = -1;
            this.progress1 = 1.0f;
        } else if (f < 0.0f) {
            this.progress1Direction = 1;
            this.progress1 = 0.0f;
        }
        float f2 = this.progress2 + ((dt / 310.0f) * this.progress2Direction);
        this.progress2 = f2;
        if (f2 > 1.0f) {
            this.progress2Direction = -1;
            this.progress2 = 1.0f;
        } else if (f2 < 0.0f) {
            this.progress2Direction = 1;
            this.progress2 = 0.0f;
        }
        float f3 = this.progress3 + ((dt / 320.0f) * this.progress3Direction);
        this.progress3 = f3;
        if (f3 > 1.0f) {
            this.progress3Direction = -1;
            this.progress3 = 1.0f;
        } else if (f3 < 0.0f) {
            this.progress3Direction = 1;
            this.progress3 = 0.0f;
        }
        this.parentView.invalidate();
    }

    public void start() {
        if (this.started) {
            return;
        }
        this.lastUpdateTime = System.currentTimeMillis();
        this.started = true;
        this.parentView.invalidate();
    }

    public void stop() {
        if (!this.started) {
            return;
        }
        this.started = false;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        this.paint.setColor(Theme.getColor(Theme.key_chat_mediaTimeText));
        int x = getBounds().left;
        int y = getBounds().top;
        for (int a = 0; a < 3; a++) {
            canvas.drawRect(AndroidUtilities.dp(2.0f) + x, AndroidUtilities.dp((this.progress1 * 7.0f) + 2.0f) + y, AndroidUtilities.dp(4.0f) + x, AndroidUtilities.dp(10.0f) + y, this.paint);
            canvas.drawRect(AndroidUtilities.dp(5.0f) + x, AndroidUtilities.dp((this.progress2 * 7.0f) + 2.0f) + y, AndroidUtilities.dp(7.0f) + x, AndroidUtilities.dp(10.0f) + y, this.paint);
            canvas.drawRect(AndroidUtilities.dp(8.0f) + x, AndroidUtilities.dp((this.progress3 * 7.0f) + 2.0f) + y, AndroidUtilities.dp(10.0f) + x, AndroidUtilities.dp(10.0f) + y, this.paint);
        }
        if (this.started) {
            update();
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
        return 0;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return AndroidUtilities.dp(12.0f);
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return AndroidUtilities.dp(12.0f);
    }
}
