package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.media.MediaMetadataRetriever;
import android.os.AsyncTask;
import android.view.MotionEvent;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class VideoTimelinePlayView extends View {
    private static final Object sync = new Object();
    private float bufferedProgress;
    private AsyncTask<Integer, Integer, Bitmap> currentTask;
    private VideoTimelineViewDelegate delegate;
    private Drawable drawableLeft;
    private Drawable drawableRight;
    private int frameHeight;
    private long frameTimeOffset;
    private int frameWidth;
    private ArrayList<Bitmap> frames;
    private int framesToLoad;
    private boolean isRoundFrames;
    private int lastWidth;
    private float maxProgressDiff;
    private MediaMetadataRetriever mediaMetadataRetriever;
    private float minProgressDiff;
    private Paint paint;
    private Paint paint2;
    private float playProgress;
    private float pressDx;
    private boolean pressedLeft;
    private boolean pressedPlay;
    private boolean pressedRight;
    private float progressLeft;
    private float progressRight;
    private android.graphics.Rect rect1;
    private android.graphics.Rect rect2;
    private RectF rect3;
    private long videoLength;

    public interface VideoTimelineViewDelegate {
        void didStartDragging();

        void didStopDragging();

        void onLeftProgressChanged(float f);

        void onPlayProgressChanged(float f);

        void onRightProgressChanged(float f);
    }

    public VideoTimelinePlayView(Context context) {
        super(context);
        this.progressRight = 1.0f;
        this.playProgress = 0.5f;
        this.bufferedProgress = 0.5f;
        this.frames = new ArrayList<>();
        this.maxProgressDiff = 1.0f;
        this.minProgressDiff = 0.0f;
        this.rect3 = new RectF();
        Paint paint = new Paint(1);
        this.paint = paint;
        paint.setColor(-1);
        Paint paint2 = new Paint();
        this.paint2 = paint2;
        paint2.setColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        Drawable drawable = context.getResources().getDrawable(R.drawable.video_cropleft);
        this.drawableLeft = drawable;
        drawable.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
        Drawable drawable2 = context.getResources().getDrawable(R.drawable.video_cropright);
        this.drawableRight = drawable2;
        drawable2.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
    }

    public float getProgress() {
        return this.playProgress;
    }

    public float getLeftProgress() {
        return this.progressLeft;
    }

    public float getRightProgress() {
        return this.progressRight;
    }

    public void setMinProgressDiff(float value) {
        this.minProgressDiff = value;
    }

    public void setMaxProgressDiff(float value) {
        this.maxProgressDiff = value;
        float f = this.progressRight;
        float f2 = this.progressLeft;
        if (f - f2 > value) {
            this.progressRight = f2 + value;
            invalidate();
        }
    }

    public void setRoundFrames(boolean value) {
        this.isRoundFrames = value;
        if (value) {
            this.rect1 = new android.graphics.Rect(AndroidUtilities.dp(14.0f), AndroidUtilities.dp(14.0f), AndroidUtilities.dp(42.0f), AndroidUtilities.dp(42.0f));
            this.rect2 = new android.graphics.Rect();
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (event == null) {
            return false;
        }
        float x = event.getX();
        float y = event.getY();
        int width = getMeasuredWidth() - AndroidUtilities.dp(32.0f);
        int startX = ((int) (width * this.progressLeft)) + AndroidUtilities.dp(16.0f);
        float f = this.progressLeft;
        int playX = ((int) (width * (f + ((this.progressRight - f) * this.playProgress)))) + AndroidUtilities.dp(16.0f);
        int endX = ((int) (width * this.progressRight)) + AndroidUtilities.dp(16.0f);
        if (event.getAction() == 0) {
            getParent().requestDisallowInterceptTouchEvent(true);
            if (this.mediaMetadataRetriever == null) {
                return false;
            }
            int additionWidth = AndroidUtilities.dp(12.0f);
            int additionWidthPlay = AndroidUtilities.dp(8.0f);
            if (playX - additionWidthPlay <= x && x <= playX + additionWidthPlay && y >= 0.0f && y <= getMeasuredHeight()) {
                VideoTimelineViewDelegate videoTimelineViewDelegate = this.delegate;
                if (videoTimelineViewDelegate != null) {
                    videoTimelineViewDelegate.didStartDragging();
                }
                this.pressedPlay = true;
                this.pressDx = (int) (x - playX);
                invalidate();
                return true;
            }
            if (startX - additionWidth <= x && x <= startX + additionWidth && y >= 0.0f && y <= getMeasuredHeight()) {
                VideoTimelineViewDelegate videoTimelineViewDelegate2 = this.delegate;
                if (videoTimelineViewDelegate2 != null) {
                    videoTimelineViewDelegate2.didStartDragging();
                }
                this.pressedLeft = true;
                this.pressDx = (int) (x - startX);
                invalidate();
                return true;
            }
            if (endX - additionWidth <= x && x <= endX + additionWidth && y >= 0.0f && y <= getMeasuredHeight()) {
                VideoTimelineViewDelegate videoTimelineViewDelegate3 = this.delegate;
                if (videoTimelineViewDelegate3 != null) {
                    videoTimelineViewDelegate3.didStartDragging();
                }
                this.pressedRight = true;
                this.pressDx = (int) (x - endX);
                invalidate();
                return true;
            }
        } else if (event.getAction() == 1 || event.getAction() == 3) {
            if (this.pressedLeft) {
                VideoTimelineViewDelegate videoTimelineViewDelegate4 = this.delegate;
                if (videoTimelineViewDelegate4 != null) {
                    videoTimelineViewDelegate4.didStopDragging();
                }
                this.pressedLeft = false;
                return true;
            }
            if (this.pressedRight) {
                VideoTimelineViewDelegate videoTimelineViewDelegate5 = this.delegate;
                if (videoTimelineViewDelegate5 != null) {
                    videoTimelineViewDelegate5.didStopDragging();
                }
                this.pressedRight = false;
                return true;
            }
            if (this.pressedPlay) {
                VideoTimelineViewDelegate videoTimelineViewDelegate6 = this.delegate;
                if (videoTimelineViewDelegate6 != null) {
                    videoTimelineViewDelegate6.didStopDragging();
                }
                this.pressedPlay = false;
                return true;
            }
        } else if (event.getAction() == 2) {
            if (this.pressedPlay) {
                float fDp = (((int) (x - this.pressDx)) - AndroidUtilities.dp(16.0f)) / width;
                this.playProgress = fDp;
                float f2 = this.progressLeft;
                if (fDp < f2) {
                    this.playProgress = f2;
                } else {
                    float f3 = this.progressRight;
                    if (fDp > f3) {
                        this.playProgress = f3;
                    }
                }
                float f4 = this.playProgress;
                float f5 = this.progressLeft;
                float f6 = this.progressRight;
                float f7 = (f4 - f5) / (f6 - f5);
                this.playProgress = f7;
                VideoTimelineViewDelegate videoTimelineViewDelegate7 = this.delegate;
                if (videoTimelineViewDelegate7 != null) {
                    videoTimelineViewDelegate7.onPlayProgressChanged(f5 + ((f6 - f5) * f7));
                }
                invalidate();
                return true;
            }
            if (this.pressedLeft) {
                int startX2 = (int) (x - this.pressDx);
                if (startX2 < AndroidUtilities.dp(16.0f)) {
                    startX2 = AndroidUtilities.dp(16.0f);
                } else if (startX2 > endX) {
                    startX2 = endX;
                }
                float fDp2 = (startX2 - AndroidUtilities.dp(16.0f)) / width;
                this.progressLeft = fDp2;
                float f8 = this.progressRight;
                float f9 = f8 - fDp2;
                float f10 = this.maxProgressDiff;
                if (f9 > f10) {
                    this.progressRight = fDp2 + f10;
                } else {
                    float f11 = this.minProgressDiff;
                    if (f11 != 0.0f && f8 - fDp2 < f11) {
                        float f12 = f8 - f11;
                        this.progressLeft = f12;
                        if (f12 < 0.0f) {
                            this.progressLeft = 0.0f;
                        }
                    }
                }
                VideoTimelineViewDelegate videoTimelineViewDelegate8 = this.delegate;
                if (videoTimelineViewDelegate8 != null) {
                    videoTimelineViewDelegate8.onLeftProgressChanged(this.progressLeft);
                }
                invalidate();
                return true;
            }
            if (this.pressedRight) {
                int endX2 = (int) (x - this.pressDx);
                if (endX2 < startX) {
                    endX2 = startX;
                } else if (endX2 > AndroidUtilities.dp(16.0f) + width) {
                    endX2 = width + AndroidUtilities.dp(16.0f);
                }
                float fDp3 = (endX2 - AndroidUtilities.dp(16.0f)) / width;
                this.progressRight = fDp3;
                float f13 = this.progressLeft;
                float f14 = fDp3 - f13;
                float f15 = this.maxProgressDiff;
                if (f14 > f15) {
                    this.progressLeft = fDp3 - f15;
                } else {
                    float f16 = this.minProgressDiff;
                    if (f16 != 0.0f && fDp3 - f13 < f16) {
                        float f17 = f13 + f16;
                        this.progressRight = f17;
                        if (f17 > 1.0f) {
                            this.progressRight = 1.0f;
                        }
                    }
                }
                VideoTimelineViewDelegate videoTimelineViewDelegate9 = this.delegate;
                if (videoTimelineViewDelegate9 != null) {
                    videoTimelineViewDelegate9.onRightProgressChanged(this.progressRight);
                }
                invalidate();
                return true;
            }
        }
        return false;
    }

    public void setColor(int color) {
        this.paint.setColor(color);
    }

    public void setVideoPath(String path, float left, float right) {
        destroy();
        MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
        this.mediaMetadataRetriever = mediaMetadataRetriever;
        this.progressLeft = left;
        this.progressRight = right;
        try {
            mediaMetadataRetriever.setDataSource(path);
            String duration = this.mediaMetadataRetriever.extractMetadata(9);
            this.videoLength = Long.parseLong(duration);
        } catch (Exception e) {
            FileLog.e(e);
        }
        invalidate();
    }

    public void setDelegate(VideoTimelineViewDelegate delegate) {
        this.delegate = delegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void reloadFrames(int frameNum) {
        if (this.mediaMetadataRetriever == null) {
            return;
        }
        if (frameNum == 0) {
            if (this.isRoundFrames) {
                int iDp = AndroidUtilities.dp(56.0f);
                this.frameWidth = iDp;
                this.frameHeight = iDp;
                this.framesToLoad = (int) Math.ceil((getMeasuredWidth() - AndroidUtilities.dp(16.0f)) / (this.frameHeight / 2.0f));
            } else {
                this.frameHeight = AndroidUtilities.dp(40.0f);
                this.framesToLoad = (getMeasuredWidth() - AndroidUtilities.dp(16.0f)) / this.frameHeight;
                this.frameWidth = (int) Math.ceil((getMeasuredWidth() - AndroidUtilities.dp(16.0f)) / this.framesToLoad);
            }
            this.frameTimeOffset = this.videoLength / ((long) this.framesToLoad);
        }
        AsyncTask<Integer, Integer, Bitmap> asyncTask = new AsyncTask<Integer, Integer, Bitmap>() { // from class: im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.1
            private int frameNum = 0;

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.os.AsyncTask
            public Bitmap doInBackground(Integer... objects) {
                this.frameNum = objects[0].intValue();
                Bitmap bitmap = null;
                if (isCancelled()) {
                    return null;
                }
                try {
                    bitmap = VideoTimelinePlayView.this.mediaMetadataRetriever.getFrameAtTime(VideoTimelinePlayView.this.frameTimeOffset * ((long) this.frameNum) * 1000, 2);
                    if (isCancelled()) {
                        return null;
                    }
                    if (bitmap != null) {
                        Bitmap result = Bitmap.createBitmap(VideoTimelinePlayView.this.frameWidth, VideoTimelinePlayView.this.frameHeight, bitmap.getConfig());
                        Canvas canvas = new Canvas(result);
                        float scaleX = VideoTimelinePlayView.this.frameWidth / bitmap.getWidth();
                        float scaleY = VideoTimelinePlayView.this.frameHeight / bitmap.getHeight();
                        float scale = scaleX > scaleY ? scaleX : scaleY;
                        int w = (int) (bitmap.getWidth() * scale);
                        int h = (int) (bitmap.getHeight() * scale);
                        android.graphics.Rect srcRect = new android.graphics.Rect(0, 0, bitmap.getWidth(), bitmap.getHeight());
                        android.graphics.Rect destRect = new android.graphics.Rect((VideoTimelinePlayView.this.frameWidth - w) / 2, (VideoTimelinePlayView.this.frameHeight - h) / 2, w, h);
                        canvas.drawBitmap(bitmap, srcRect, destRect, (Paint) null);
                        bitmap.recycle();
                        return result;
                    }
                    return bitmap;
                } catch (Exception e) {
                    FileLog.e(e);
                    return bitmap;
                }
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.os.AsyncTask
            public void onPostExecute(Bitmap bitmap) {
                if (!isCancelled()) {
                    VideoTimelinePlayView.this.frames.add(bitmap);
                    VideoTimelinePlayView.this.invalidate();
                    if (this.frameNum < VideoTimelinePlayView.this.framesToLoad) {
                        VideoTimelinePlayView.this.reloadFrames(this.frameNum + 1);
                    }
                }
            }
        };
        this.currentTask = asyncTask;
        asyncTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, Integer.valueOf(frameNum), null, null);
    }

    public void destroy() {
        synchronized (sync) {
            try {
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (this.mediaMetadataRetriever != null) {
                this.mediaMetadataRetriever.release();
                this.mediaMetadataRetriever = null;
            }
        }
        for (int a = 0; a < this.frames.size(); a++) {
            Bitmap bitmap = this.frames.get(a);
            if (bitmap != null) {
                bitmap.recycle();
            }
        }
        this.frames.clear();
        AsyncTask<Integer, Integer, Bitmap> asyncTask = this.currentTask;
        if (asyncTask != null) {
            asyncTask.cancel(true);
            this.currentTask = null;
        }
    }

    public boolean isDragging() {
        return this.pressedPlay;
    }

    public void setProgress(float value) {
        this.playProgress = value;
        invalidate();
    }

    public void clearFrames() {
        for (int a = 0; a < this.frames.size(); a++) {
            Bitmap bitmap = this.frames.get(a);
            if (bitmap != null) {
                bitmap.recycle();
            }
        }
        this.frames.clear();
        AsyncTask<Integer, Integer, Bitmap> asyncTask = this.currentTask;
        if (asyncTask != null) {
            asyncTask.cancel(true);
            this.currentTask = null;
        }
        invalidate();
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
        if (this.lastWidth != widthSize) {
            clearFrames();
            this.lastWidth = widthSize;
        }
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        int width = getMeasuredWidth() - AndroidUtilities.dp(36.0f);
        float f = 16.0f;
        int startX = ((int) (width * this.progressLeft)) + AndroidUtilities.dp(16.0f);
        int endX = ((int) (width * this.progressRight)) + AndroidUtilities.dp(16.0f);
        canvas.save();
        canvas.clipRect(AndroidUtilities.dp(16.0f), AndroidUtilities.dp(4.0f), AndroidUtilities.dp(20.0f) + width, AndroidUtilities.dp(48.0f));
        if (this.frames.isEmpty() && this.currentTask == null) {
            reloadFrames(0);
        } else {
            int offset = 0;
            int a = 0;
            while (a < this.frames.size()) {
                Bitmap bitmap = this.frames.get(a);
                if (bitmap != null) {
                    int x = AndroidUtilities.dp(f) + ((this.isRoundFrames ? this.frameWidth / 2 : this.frameWidth) * offset);
                    int y = AndroidUtilities.dp(6.0f);
                    if (this.isRoundFrames) {
                        this.rect2.set(x, y, x + AndroidUtilities.dp(28.0f), y + AndroidUtilities.dp(28.0f));
                        canvas.drawBitmap(bitmap, this.rect1, this.rect2, (Paint) null);
                    } else {
                        canvas.drawBitmap(bitmap, x, y, (Paint) null);
                    }
                }
                offset++;
                a++;
                f = 16.0f;
            }
        }
        int top = AndroidUtilities.dp(6.0f);
        int end = AndroidUtilities.dp(48.0f);
        canvas.drawRect(AndroidUtilities.dp(16.0f), top, startX, AndroidUtilities.dp(46.0f), this.paint2);
        canvas.drawRect(AndroidUtilities.dp(4.0f) + endX, top, AndroidUtilities.dp(16.0f) + width + AndroidUtilities.dp(4.0f), AndroidUtilities.dp(46.0f), this.paint2);
        canvas.drawRect(startX, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f) + startX, end, this.paint);
        canvas.drawRect(AndroidUtilities.dp(2.0f) + endX, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f) + endX, end, this.paint);
        canvas.drawRect(AndroidUtilities.dp(2.0f) + startX, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f) + endX, top, this.paint);
        canvas.drawRect(AndroidUtilities.dp(2.0f) + startX, end - AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f) + endX, end, this.paint);
        canvas.restore();
        this.rect3.set(startX - AndroidUtilities.dp(8.0f), AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f) + startX, end);
        canvas.drawRoundRect(this.rect3, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), this.paint);
        this.drawableLeft.setBounds(startX - AndroidUtilities.dp(8.0f), AndroidUtilities.dp(4.0f) + ((AndroidUtilities.dp(44.0f) - AndroidUtilities.dp(18.0f)) / 2), AndroidUtilities.dp(2.0f) + startX, ((AndroidUtilities.dp(44.0f) - AndroidUtilities.dp(18.0f)) / 2) + AndroidUtilities.dp(22.0f));
        this.drawableLeft.draw(canvas);
        this.rect3.set(AndroidUtilities.dp(2.0f) + endX, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(12.0f) + endX, end);
        canvas.drawRoundRect(this.rect3, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), this.paint);
        this.drawableRight.setBounds(AndroidUtilities.dp(2.0f) + endX, AndroidUtilities.dp(4.0f) + ((AndroidUtilities.dp(44.0f) - AndroidUtilities.dp(18.0f)) / 2), AndroidUtilities.dp(12.0f) + endX, ((AndroidUtilities.dp(44.0f) - AndroidUtilities.dp(18.0f)) / 2) + AndroidUtilities.dp(22.0f));
        this.drawableRight.draw(canvas);
        float fDp = AndroidUtilities.dp(18.0f);
        float f2 = this.progressLeft;
        float cx = fDp + (width * (f2 + ((this.progressRight - f2) * this.playProgress)));
        this.rect3.set(cx - AndroidUtilities.dp(1.5f), AndroidUtilities.dp(2.0f), AndroidUtilities.dp(1.5f) + cx, AndroidUtilities.dp(50.0f));
        canvas.drawRoundRect(this.rect3, AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), this.paint2);
        canvas.drawCircle(cx, AndroidUtilities.dp(52.0f), AndroidUtilities.dp(3.5f), this.paint2);
        this.rect3.set(cx - AndroidUtilities.dp(1.0f), AndroidUtilities.dp(2.0f), AndroidUtilities.dp(1.0f) + cx, AndroidUtilities.dp(50.0f));
        canvas.drawRoundRect(this.rect3, AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), this.paint);
        canvas.drawCircle(cx, AndroidUtilities.dp(52.0f), AndroidUtilities.dp(3.0f), this.paint);
    }
}
