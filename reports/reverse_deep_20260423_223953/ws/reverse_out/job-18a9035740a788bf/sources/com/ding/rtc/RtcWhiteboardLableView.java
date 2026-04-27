package com.ding.rtc;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathEffect;
import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Handler;
import android.util.ArrayMap;
import android.util.AttributeSet;
import android.view.View;
import androidx.core.internal.view.SupportMenu;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardLableView extends View {
    private static final String TAG = "MzwaLabelView";
    private static int kMaxLaserPointNum = 30;
    private static int kMinLaserPointNum = 20;
    private static final int kRoundRadius = 2;
    private Drawable eraseDrawable;
    private final LinkedList<PointF> erasePoints;
    private final Handler handler;
    private int labelOffset;
    private Drawable laserDrawable;
    private final LinkedList<PointTime> laserPoints;
    private final Point laserPos;
    private final ArrayMap<String, CursorInfo> mCursorMap;
    private final Paint paint;
    private Drawable pencilDrawable;
    private Drawable plusDrawable;
    private final RectF rect;
    private final Runnable runnable;
    private Drawable selectDrawable;
    private boolean showEraserTrail;
    private boolean showLaser;
    private boolean showLaserTrail;
    private Drawable textDrawable;
    private int textMargin;
    private int textSize;

    static class PointTime {
        public PointF p;
        public PointF p1;
        public PointF p2;
        public long ts;

        PointTime(PointF pt, long t) {
            this.p = pt;
            this.ts = t;
            this.p1 = new PointF(pt.x, pt.y);
            this.p2 = new PointF(pt.x, pt.y);
        }
    }

    static class CursorInfo {
        int color;
        String name;
        int type;
        float x;
        float y;

        CursorInfo() {
        }
    }

    public RtcWhiteboardLableView(Context context) {
        this(context, null);
    }

    public RtcWhiteboardLableView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.labelOffset = 32;
        this.textSize = 24;
        this.textMargin = 3;
        this.paint = new Paint();
        this.rect = new RectF();
        this.laserPoints = new LinkedList<>();
        this.erasePoints = new LinkedList<>();
        this.laserPos = new Point();
        this.showLaser = false;
        this.showLaserTrail = true;
        this.showEraserTrail = false;
        this.handler = new Handler();
        this.runnable = new Runnable() { // from class: com.ding.rtc.RtcWhiteboardLableView.1
            @Override // java.lang.Runnable
            public void run() {
                long ts = System.currentTimeMillis();
                while (!RtcWhiteboardLableView.this.laserPoints.isEmpty() && ((PointTime) RtcWhiteboardLableView.this.laserPoints.getFirst()).ts < ts - 300) {
                    RtcWhiteboardLableView.this.laserPoints.removeFirst();
                }
                if (!RtcWhiteboardLableView.this.laserPoints.isEmpty()) {
                    RtcWhiteboardLableView.this.handler.postDelayed(this, 20L);
                }
                RtcWhiteboardLableView.this.invalidate();
            }
        };
        this.mCursorMap = new ArrayMap<>();
        loadDrawable();
        this.paint.setStyle(Paint.Style.FILL);
        this.paint.setTextSize(this.textSize);
    }

    public void setLabelSize(int textSz, int margin) {
        this.textSize = textSz;
        this.textMargin = margin;
        this.labelOffset = (margin * 2) + textSz + 2;
        this.paint.setTextSize(textSz);
    }

    public void addCursor(String labelId, String name) {
        CursorInfo info = this.mCursorMap.get(labelId);
        if (info == null) {
            CursorInfo cursor = new CursorInfo();
            cursor.name = name;
            this.mCursorMap.put(labelId, cursor);
        }
    }

    public void removeCursor(String labelId) {
        this.mCursorMap.remove(labelId);
        invalidate();
    }

    public void updateCursor(String labelId, float x, float y, int color, int type, String name) {
        CursorInfo info = this.mCursorMap.get(labelId);
        if (info == null) {
            info = new CursorInfo();
            info.name = name;
        }
        info.x = x;
        info.y = y;
        info.color = color;
        info.type = type;
        this.mCursorMap.put(labelId, info);
        invalidate();
    }

    public void updateLaserPoint(float x, float y) {
        if (this.laserPoints.isEmpty()) {
            this.handler.postDelayed(this.runnable, 20L);
        }
        if (this.laserPoints.size() == kMaxLaserPointNum) {
            this.laserPoints.removeFirst();
        }
        if (this.laserPoints.size() > 1) {
            PointTime pt = this.laserPoints.pollLast();
            PointF p0 = this.laserPoints.getLast().p;
            PointF p1 = pt.p;
            float x01 = (p0.x + p1.x) / 2.0f;
            float y01 = (p0.y + p1.y) / 2.0f;
            float d01 = (float) Math.sqrt(((p1.x - p0.x) * (p1.x - p0.x)) + ((p1.y - p0.y) * (p1.y - p0.y)));
            float x12 = (p1.x + x) / 2.0f;
            float y12 = (p1.y + y) / 2.0f;
            float d12 = (float) Math.sqrt(((p1.x - x) * (p1.x - x)) + ((p1.y - y) * (p1.y - y)));
            float k = d01 / (d01 + d12);
            float xx = ((x12 - x01) * k) + x01;
            float yy = ((y12 - y01) * k) + y01;
            pt.p1.x = p1.x + ((x01 - xx) * 0.5f);
            pt.p1.y = p1.y + ((y01 - yy) * 0.5f);
            pt.p2.x = p1.x + ((x12 - xx) * 0.5f);
            pt.p2.y = p1.y + ((y12 - yy) * 0.5f);
            this.laserPoints.add(pt);
        }
        this.laserPoints.add(new PointTime(new PointF(x, y), System.currentTimeMillis()));
        this.laserPos.x = (int) x;
        this.laserPos.y = (int) y;
        invalidate();
    }

    public void enableLaser(boolean enable) {
        if (enable) {
            this.laserPos.x = -1;
            this.laserPos.y = -1;
        }
        if (this.showLaser != enable) {
            this.showLaser = enable;
            invalidate();
        }
    }

    public void enableLaserTrail(boolean enable) {
        if (this.showLaserTrail != enable) {
            this.showLaserTrail = enable;
            invalidate();
        }
    }

    public void enableEraseTrail(boolean enable) {
        if (this.showEraserTrail != enable) {
            this.showEraserTrail = enable;
        }
    }

    public void updateErasePoint(float x, float y) {
        if (this.showEraserTrail) {
            this.erasePoints.add(new PointF(x, y));
            invalidate();
        }
    }

    public void clearEraseTrail() {
        this.erasePoints.clear();
        invalidate();
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        for (Map.Entry<String, CursorInfo> entry : this.mCursorMap.entrySet()) {
            CursorInfo info = entry.getValue();
            float ty = info.y - this.labelOffset;
            drawIcon(canvas, info.type, (int) info.x, (int) info.y);
            float tw = this.paint.measureText(info.name) + 6.0f;
            this.paint.setColor(info.color);
            if (Build.VERSION.SDK_INT >= 21) {
                canvas.drawRoundRect(info.x, (ty - this.textSize) - (this.textMargin * 2), info.x + tw, ty, 2.0f, 2.0f, this.paint);
            } else {
                this.rect.set(info.x, (ty - this.textSize) - (this.textMargin * 2), info.x + tw, ty);
                canvas.drawRoundRect(this.rect, 2.0f, 2.0f, this.paint);
            }
            this.paint.setColor(-1);
            canvas.drawText(info.name, info.x + this.textMargin, ty - (r7 * 2), this.paint);
        }
        if (this.showLaserTrail) {
            drawLaserTrail(canvas);
        }
        if (this.showLaser && this.laserPos.x >= 0 && this.laserPos.y >= 0) {
            drawLaser(canvas, 0, this.laserPos.x, this.laserPos.y);
        }
        if (this.showEraserTrail) {
            drawEraseTrail(canvas);
        }
    }

    private void loadDrawable() {
        this.selectDrawable = getResources().getDrawable(R.drawable.move);
        this.eraseDrawable = getResources().getDrawable(R.drawable.eraser);
        this.pencilDrawable = getResources().getDrawable(R.drawable.pencil);
        this.plusDrawable = getResources().getDrawable(R.drawable.plus);
        this.textDrawable = getResources().getDrawable(R.drawable.text);
        this.laserDrawable = getResources().getDrawable(R.drawable.laser);
    }

    private void drawIcon(Canvas canvas, int type, int x, int y) {
        if (type == 1) {
            this.pencilDrawable.setBounds(x, y - 24, x + 24, y);
            this.pencilDrawable.draw(canvas);
            return;
        }
        if (type == 2) {
            this.selectDrawable.setBounds(x - 12, y - 12, x + 12, y + 12);
            this.selectDrawable.draw(canvas);
            return;
        }
        if (type == 3) {
            this.eraseDrawable.setBounds(x, y - 24, x + 24, y);
            this.eraseDrawable.draw(canvas);
        } else if (type == 4) {
            this.textDrawable.setBounds(x, y, x + 24, y + 24);
            this.textDrawable.draw(canvas);
        } else if (type == 5) {
            this.plusDrawable.setBounds(x - 12, y - 12, x + 12, y + 12);
            this.plusDrawable.draw(canvas);
        }
    }

    private void drawLaser(Canvas canvas, int type, int x, int y) {
        this.laserDrawable.setBounds(x - 20, y - 20, x + 20, y + 20);
        this.laserDrawable.draw(canvas);
    }

    private void drawLaserTrail(Canvas canvas) {
        LinkedList<PointTime> points = this.laserPoints;
        ListIterator<PointTime> it1 = points.listIterator();
        ListIterator<PointTime> it2 = points.listIterator();
        if (it2.hasNext()) {
            it2.next();
        }
        int size = points.size();
        int i = 0;
        while (it2.hasNext()) {
            PointTime p1 = it1.next();
            PointTime p2 = it2.next();
            this.paint.setColor(Color.argb((i * 255) / size, 255, 0, 0));
            this.paint.setStrokeWidth((i * 15.0f) / size);
            Path path = new Path();
            path.moveTo(p1.p.x, p1.p.y);
            path.cubicTo(p1.p2.x, p1.p2.y, p2.p1.x, p2.p1.y, p2.p.x, p2.p.y);
            this.paint.setStyle(Paint.Style.STROKE);
            canvas.drawPath(path, this.paint);
            i++;
        }
    }

    private void drawEraseTrail(Canvas canvas) {
        Path path = new Path();
        PathEffect dashEffect = new DashPathEffect(new float[]{20.0f, 20.0f}, 0.0f);
        ListIterator<PointF> it = this.erasePoints.listIterator();
        PointF p1 = new PointF();
        new PointF();
        if (it.hasNext()) {
            PointF p12 = it.next();
            p1 = p12;
            path.moveTo(p1.x, p1.y);
        }
        while (it.hasNext()) {
            PointF p2 = it.next();
            PointF pc = new PointF((p2.x + p1.x) / 2.0f, (p2.y + p1.y) / 2.0f);
            path.quadTo(p1.x, p1.y, pc.x, pc.y);
            p1 = p2;
        }
        this.paint.setStrokeWidth(5.0f);
        this.paint.setColor(SupportMenu.CATEGORY_MASK);
        Paint.Style oldStyle = this.paint.getStyle();
        this.paint.setStyle(Paint.Style.STROKE);
        PathEffect oldPathEffect = this.paint.getPathEffect();
        this.paint.setPathEffect(dashEffect);
        canvas.drawPath(path, this.paint);
        this.paint.setStyle(oldStyle);
        this.paint.setPathEffect(oldPathEffect);
    }
}
