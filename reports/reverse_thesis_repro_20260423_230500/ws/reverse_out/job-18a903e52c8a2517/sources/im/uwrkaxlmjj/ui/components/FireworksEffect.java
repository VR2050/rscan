package im.uwrkaxlmjj.ui.components;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Build;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.ArrayList;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class FireworksEffect {
    private long lastAnimationTime;
    private Paint particlePaint;
    final float angleDiff = 1.0471976f;
    private ArrayList<Particle> particles = new ArrayList<>();
    private ArrayList<Particle> freeParticles = new ArrayList<>();

    private class Particle {
        float alpha;
        int color;
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
            if (this.type == 0) {
                FireworksEffect.this.particlePaint.setColor(this.color);
                FireworksEffect.this.particlePaint.setStrokeWidth(AndroidUtilities.dp(1.5f) * this.scale);
                FireworksEffect.this.particlePaint.setAlpha((int) (this.alpha * 255.0f));
                canvas.drawPoint(this.x, this.y, FireworksEffect.this.particlePaint);
            }
        }
    }

    public FireworksEffect() {
        Paint paint = new Paint(1);
        this.particlePaint = paint;
        paint.setStrokeWidth(AndroidUtilities.dp(1.5f));
        this.particlePaint.setColor(Theme.getColor(Theme.key_actionBarDefaultTitle) & (-1644826));
        this.particlePaint.setStrokeCap(Paint.Cap.ROUND);
        this.particlePaint.setStyle(Paint.Style.STROKE);
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
                particle.alpha = 1.0f - AndroidUtilities.decelerateInterpolator.getInterpolation(particle.currentTime / particle.lifeTime);
                particle.x += ((particle.vx * particle.velocity) * dt) / 500.0f;
                particle.y += ((particle.vy * particle.velocity) * dt) / 500.0f;
                particle.vy += dt / 100.0f;
                particle.currentTime += dt;
            }
            a++;
        }
    }

    public void onDraw(View parent, Canvas canvas) {
        int color;
        Particle newParticle;
        if (parent == null || canvas == null) {
            return;
        }
        int count = this.particles.size();
        for (int a = 0; a < count; a++) {
            Particle particle = this.particles.get(a);
            particle.draw(canvas);
        }
        if (Utilities.random.nextBoolean()) {
            if (this.particles.size() + 8 < 150) {
                int statusBarHeight = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
                float cx = Utilities.random.nextFloat() * parent.getMeasuredWidth();
                float cy = statusBarHeight + (Utilities.random.nextFloat() * ((parent.getMeasuredHeight() - AndroidUtilities.dp(20.0f)) - statusBarHeight));
                int iNextInt = Utilities.random.nextInt(4);
                if (iNextInt == 0) {
                    color = -13357350;
                } else if (iNextInt == 1) {
                    color = -843755;
                } else if (iNextInt == 2) {
                    color = -207021;
                } else if (iNextInt == 3) {
                    color = -15088582;
                } else {
                    color = -5752;
                }
                int a2 = 0;
                for (int i = 8; a2 < i; i = 8) {
                    int angle = Utilities.random.nextInt(JavaScreenCapturer.DEGREE_270) - 225;
                    float vx = (float) Math.cos(((double) angle) * 0.017453292519943295d);
                    float cx2 = cx;
                    float vy = (float) Math.sin(((double) angle) * 0.017453292519943295d);
                    if (this.freeParticles.isEmpty()) {
                        newParticle = new Particle();
                    } else {
                        newParticle = this.freeParticles.get(0);
                        this.freeParticles.remove(0);
                    }
                    newParticle.x = cx2;
                    newParticle.y = cy;
                    newParticle.vx = vx * 1.5f;
                    newParticle.vy = vy;
                    newParticle.color = color;
                    newParticle.alpha = 1.0f;
                    newParticle.currentTime = 0.0f;
                    newParticle.scale = Math.max(1.0f, Utilities.random.nextFloat() * 1.5f);
                    newParticle.type = 0;
                    newParticle.lifeTime = Utilities.random.nextInt(1000) + 1000;
                    newParticle.velocity = (Utilities.random.nextFloat() * 4.0f) + 20.0f;
                    this.particles.add(newParticle);
                    a2++;
                    cx = cx2;
                }
            }
        }
        long newTime = System.currentTimeMillis();
        long dt = Math.min(17L, newTime - this.lastAnimationTime);
        updateParticles(dt);
        this.lastAnimationTime = newTime;
        parent.invalidate();
    }
}
