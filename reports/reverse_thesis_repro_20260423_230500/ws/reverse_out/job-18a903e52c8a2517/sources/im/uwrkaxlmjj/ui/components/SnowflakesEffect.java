package im.uwrkaxlmjj.ui.components;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Build;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class SnowflakesEffect {
    private long lastAnimationTime;
    private Paint particlePaint;
    private Paint particleThinPaint;
    final float angleDiff = 1.0471976f;
    private ArrayList<Particle> particles = new ArrayList<>();
    private ArrayList<Particle> freeParticles = new ArrayList<>();

    private class Particle {
        float alpha;
        float currentTime;
        float lifeTime;
        float scale;
        int type;
        float velocity;
        float vx;
        float vy;
        float x;
        float y;

        private Particle() {
        }

        public void draw(Canvas canvas) {
            if (this.type != 0) {
                SnowflakesEffect.this.particleThinPaint.setAlpha((int) (this.alpha * 255.0f));
                float angle = -1.5707964f;
                float px = AndroidUtilities.dpf2(2.0f) * 2.0f * this.scale;
                float px1 = (-AndroidUtilities.dpf2(0.57f)) * 2.0f * this.scale;
                float py1 = AndroidUtilities.dpf2(1.55f) * 2.0f * this.scale;
                int a = 0;
                while (a < 6) {
                    float x1 = ((float) Math.cos(angle)) * px;
                    float y1 = ((float) Math.sin(angle)) * px;
                    float cx = x1 * 0.66f;
                    float cy = 0.66f * y1;
                    float f = this.x;
                    float f2 = this.y;
                    canvas.drawLine(f, f2, f + x1, f2 + y1, SnowflakesEffect.this.particleThinPaint);
                    float angle2 = (float) (((double) angle) - 1.5707963267948966d);
                    float x12 = (float) ((Math.cos(angle2) * ((double) px1)) - (Math.sin(angle2) * ((double) py1)));
                    int a2 = a;
                    float px2 = px;
                    float y12 = (float) ((Math.sin(angle2) * ((double) px1)) + (Math.cos(angle2) * ((double) py1)));
                    float f3 = this.x;
                    float f4 = this.y;
                    canvas.drawLine(f3 + cx, f4 + cy, f3 + x12, f4 + y12, SnowflakesEffect.this.particleThinPaint);
                    float x13 = (float) (((-Math.cos(angle2)) * ((double) px1)) - (Math.sin(angle2) * ((double) py1)));
                    float px12 = px1;
                    float y13 = (float) (((-Math.sin(angle2)) * ((double) px1)) + (Math.cos(angle2) * ((double) py1)));
                    float f5 = this.x;
                    float f6 = this.y;
                    canvas.drawLine(f5 + cx, f6 + cy, f5 + x13, f6 + y13, SnowflakesEffect.this.particleThinPaint);
                    angle += 1.0471976f;
                    a = a2 + 1;
                    px1 = px12;
                    px = px2;
                }
                return;
            }
            SnowflakesEffect.this.particlePaint.setAlpha((int) (this.alpha * 255.0f));
            canvas.drawPoint(this.x, this.y, SnowflakesEffect.this.particlePaint);
        }
    }

    public SnowflakesEffect() {
        Paint paint = new Paint(1);
        this.particlePaint = paint;
        paint.setStrokeWidth(AndroidUtilities.dp(1.5f));
        this.particlePaint.setColor(Theme.getColor(Theme.key_actionBarDefaultTitle) & (-1644826));
        this.particlePaint.setStrokeCap(Paint.Cap.ROUND);
        this.particlePaint.setStyle(Paint.Style.STROKE);
        Paint paint2 = new Paint(1);
        this.particleThinPaint = paint2;
        paint2.setStrokeWidth(AndroidUtilities.dp(0.5f));
        this.particleThinPaint.setColor(Theme.getColor(Theme.key_actionBarDefaultTitle) & (-1644826));
        this.particleThinPaint.setStrokeCap(Paint.Cap.ROUND);
        this.particleThinPaint.setStyle(Paint.Style.STROKE);
        for (int a = 0; a < 20; a++) {
            this.freeParticles.add(new Particle());
        }
    }

    private void updateParticles(long dt) {
        int count = this.particles.size();
        int a = 0;
        while (a < count) {
            Particle particle = this.particles.get(a);
            if (particle.currentTime >= particle.lifeTime) {
                if (this.freeParticles.size() < 40) {
                    this.freeParticles.add(particle);
                }
                this.particles.remove(a);
                a--;
                count--;
            } else {
                if (particle.currentTime < 200.0f) {
                    particle.alpha = AndroidUtilities.accelerateInterpolator.getInterpolation(particle.currentTime / 200.0f);
                } else {
                    particle.alpha = 1.0f - AndroidUtilities.decelerateInterpolator.getInterpolation((particle.currentTime - 200.0f) / (particle.lifeTime - 200.0f));
                }
                particle.x += ((particle.vx * particle.velocity) * dt) / 500.0f;
                particle.y += ((particle.vy * particle.velocity) * dt) / 500.0f;
                particle.currentTime += dt;
            }
            a++;
        }
    }

    public void onDraw(View parent, Canvas canvas) {
        Particle newParticle;
        if (parent == null || canvas == null) {
            return;
        }
        int count = this.particles.size();
        for (int a = 0; a < count; a++) {
            Particle particle = this.particles.get(a);
            particle.draw(canvas);
        }
        if (Utilities.random.nextFloat() > 0.7f && this.particles.size() < 100) {
            int statusBarHeight = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
            float cx = Utilities.random.nextFloat() * parent.getMeasuredWidth();
            float cy = statusBarHeight + (Utilities.random.nextFloat() * ((parent.getMeasuredHeight() - AndroidUtilities.dp(20.0f)) - statusBarHeight));
            int angle = (Utilities.random.nextInt(40) - 20) + 90;
            float vx = (float) Math.cos(((double) angle) * 0.017453292519943295d);
            float vy = (float) Math.sin(((double) angle) * 0.017453292519943295d);
            if (!this.freeParticles.isEmpty()) {
                newParticle = this.freeParticles.get(0);
                this.freeParticles.remove(0);
            } else {
                newParticle = new Particle();
            }
            newParticle.x = cx;
            newParticle.y = cy;
            newParticle.vx = vx;
            newParticle.vy = vy;
            newParticle.alpha = 0.0f;
            newParticle.currentTime = 0.0f;
            newParticle.scale = Utilities.random.nextFloat() * 1.2f;
            newParticle.type = Utilities.random.nextInt(2);
            newParticle.lifeTime = Utilities.random.nextInt(100) + 2000;
            newParticle.velocity = (Utilities.random.nextFloat() * 4.0f) + 20.0f;
            this.particles.add(newParticle);
        }
        long newTime = System.currentTimeMillis();
        long dt = Math.min(17L, newTime - this.lastAnimationTime);
        updateParticles(dt);
        this.lastAnimationTime = newTime;
        parent.invalidate();
    }
}
