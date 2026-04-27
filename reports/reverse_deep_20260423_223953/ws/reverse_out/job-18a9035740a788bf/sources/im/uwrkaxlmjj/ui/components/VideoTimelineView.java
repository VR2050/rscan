package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.media.MediaMetadataRetriever;
import android.os.AsyncTask;
import android.view.MotionEvent;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class VideoTimelineView extends View {
    private static final Object sync = new Object();
    private AsyncTask<Integer, Integer, Bitmap> currentTask;
    private VideoTimelineViewDelegate delegate;
    private int frameHeight;
    private long frameTimeOffset;
    private int frameWidth;
    private ArrayList<Bitmap> frames;
    private int framesToLoad;
    private boolean isRoundFrames;
    private float maxProgressDiff;
    private MediaMetadataRetriever mediaMetadataRetriever;
    private float minProgressDiff;
    private Paint paint;
    private Paint paint2;
    private float pressDx;
    private boolean pressedLeft;
    private boolean pressedRight;
    private float progressLeft;
    private float progressRight;
    private android.graphics.Rect rect1;
    private android.graphics.Rect rect2;
    private long videoLength;

    public interface VideoTimelineViewDelegate {
        void didStartDragging();

        void didStopDragging();

        void onLeftProgressChanged(float f);

        void onRightProgressChanged(float f);
    }

    public VideoTimelineView(Context context) {
        super(context);
        this.progressRight = 1.0f;
        this.frames = new ArrayList<>();
        this.maxProgressDiff = 1.0f;
        this.minProgressDiff = 0.0f;
        Paint paint = new Paint(1);
        this.paint = paint;
        paint.setColor(-1);
        Paint paint2 = new Paint();
        this.paint2 = paint2;
        paint2.setColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
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
        int endX = ((int) (width * this.progressRight)) + AndroidUtilities.dp(16.0f);
        if (event.getAction() == 0) {
            getParent().requestDisallowInterceptTouchEvent(true);
            if (this.mediaMetadataRetriever == null) {
                return false;
            }
            int additionWidth = AndroidUtilities.dp(12.0f);
            if (startX - additionWidth <= x && x <= startX + additionWidth && y >= 0.0f && y <= getMeasuredHeight()) {
                VideoTimelineViewDelegate videoTimelineViewDelegate = this.delegate;
                if (videoTimelineViewDelegate != null) {
                    videoTimelineViewDelegate.didStartDragging();
                }
                this.pressedLeft = true;
                this.pressDx = (int) (x - startX);
                invalidate();
                return true;
            }
            if (endX - additionWidth <= x && x <= endX + additionWidth && y >= 0.0f && y <= getMeasuredHeight()) {
                VideoTimelineViewDelegate videoTimelineViewDelegate2 = this.delegate;
                if (videoTimelineViewDelegate2 != null) {
                    videoTimelineViewDelegate2.didStartDragging();
                }
                this.pressedRight = true;
                this.pressDx = (int) (x - endX);
                invalidate();
                return true;
            }
        } else if (event.getAction() == 1 || event.getAction() == 3) {
            if (this.pressedLeft) {
                VideoTimelineViewDelegate videoTimelineViewDelegate3 = this.delegate;
                if (videoTimelineViewDelegate3 != null) {
                    videoTimelineViewDelegate3.didStopDragging();
                }
                this.pressedLeft = false;
                return true;
            }
            if (this.pressedRight) {
                VideoTimelineViewDelegate videoTimelineViewDelegate4 = this.delegate;
                if (videoTimelineViewDelegate4 != null) {
                    videoTimelineViewDelegate4.didStopDragging();
                }
                this.pressedRight = false;
                return true;
            }
        } else if (event.getAction() == 2) {
            if (this.pressedLeft) {
                int startX2 = (int) (x - this.pressDx);
                if (startX2 < AndroidUtilities.dp(16.0f)) {
                    startX2 = AndroidUtilities.dp(16.0f);
                } else if (startX2 > endX) {
                    startX2 = endX;
                }
                float fDp = (startX2 - AndroidUtilities.dp(16.0f)) / width;
                this.progressLeft = fDp;
                float f = this.progressRight;
                float f2 = f - fDp;
                float f3 = this.maxProgressDiff;
                if (f2 > f3) {
                    this.progressRight = fDp + f3;
                } else {
                    float f4 = this.minProgressDiff;
                    if (f4 != 0.0f && f - fDp < f4) {
                        float f5 = f - f4;
                        this.progressLeft = f5;
                        if (f5 < 0.0f) {
                            this.progressLeft = 0.0f;
                        }
                    }
                }
                VideoTimelineViewDelegate videoTimelineViewDelegate5 = this.delegate;
                if (videoTimelineViewDelegate5 != null) {
                    videoTimelineViewDelegate5.onLeftProgressChanged(this.progressLeft);
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
                float fDp2 = (endX2 - AndroidUtilities.dp(16.0f)) / width;
                this.progressRight = fDp2;
                float f6 = this.progressLeft;
                float f7 = fDp2 - f6;
                float f8 = this.maxProgressDiff;
                if (f7 > f8) {
                    this.progressLeft = fDp2 - f8;
                } else {
                    float f9 = this.minProgressDiff;
                    if (f9 != 0.0f && fDp2 - f6 < f9) {
                        float f10 = f6 + f9;
                        this.progressRight = f10;
                        if (f10 > 1.0f) {
                            this.progressRight = 1.0f;
                        }
                    }
                }
                VideoTimelineViewDelegate videoTimelineViewDelegate6 = this.delegate;
                if (videoTimelineViewDelegate6 != null) {
                    videoTimelineViewDelegate6.onRightProgressChanged(this.progressRight);
                }
                invalidate();
                return true;
            }
        }
        return false;
    }

    public void setColor(int color) {
        this.paint.setColor(color);
        invalidate();
    }

    public void setVideoPath(String path) {
        destroy();
        MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
        this.mediaMetadataRetriever = mediaMetadataRetriever;
        this.progressLeft = 0.0f;
        this.progressRight = 1.0f;
        try {
            mediaMetadataRetriever.setDataSource(path);
            String duration = this.mediaMetadataRetriever.extractMetadata(9);
            this.videoLength = Long.parseLong(duration);
        } catch (Exception e) {
            FileLog.e(e);
        }
        invalidate();
    }

    public void setDelegate(VideoTimelineViewDelegate videoTimelineViewDelegate) {
        this.delegate = videoTimelineViewDelegate;
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
        AsyncTask<Integer, Integer, Bitmap> asyncTask = new AsyncTask<Integer, Integer, Bitmap>() { // from class: im.uwrkaxlmjj.ui.components.VideoTimelineView.1
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
                    bitmap = VideoTimelineView.this.mediaMetadataRetriever.getFrameAtTime(VideoTimelineView.this.frameTimeOffset * ((long) this.frameNum) * 1000, 2);
                    if (isCancelled()) {
                        return null;
                    }
                    if (bitmap != null) {
                        Bitmap result = Bitmap.createBitmap(VideoTimelineView.this.frameWidth, VideoTimelineView.this.frameHeight, bitmap.getConfig());
                        Canvas canvas = new Canvas(result);
                        float scaleX = VideoTimelineView.this.frameWidth / bitmap.getWidth();
                        float scaleY = VideoTimelineView.this.frameHeight / bitmap.getHeight();
                        float scale = scaleX > scaleY ? scaleX : scaleY;
                        int w = (int) (bitmap.getWidth() * scale);
                        int h = (int) (bitmap.getHeight() * scale);
                        android.graphics.Rect srcRect = new android.graphics.Rect(0, 0, bitmap.getWidth(), bitmap.getHeight());
                        android.graphics.Rect destRect = new android.graphics.Rect((VideoTimelineView.this.frameWidth - w) / 2, (VideoTimelineView.this.frameHeight - h) / 2, w, h);
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
                    VideoTimelineView.this.frames.add(bitmap);
                    VideoTimelineView.this.invalidate();
                    if (this.frameNum < VideoTimelineView.this.framesToLoad) {
                        VideoTimelineView.this.reloadFrames(this.frameNum + 1);
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
    protected void onDraw(Canvas canvas) {
        int width = getMeasuredWidth() - AndroidUtilities.dp(36.0f);
        int startX = ((int) (width * this.progressLeft)) + AndroidUtilities.dp(16.0f);
        int endX = ((int) (width * this.progressRight)) + AndroidUtilities.dp(16.0f);
        canvas.save();
        canvas.clipRect(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(20.0f) + width, getMeasuredHeight());
        if (this.frames.isEmpty() && this.currentTask == null) {
            reloadFrames(0);
        } else {
            int offset = 0;
            for (int a = 0; a < this.frames.size(); a++) {
                Bitmap bitmap = this.frames.get(a);
                if (bitmap != null) {
                    int x = AndroidUtilities.dp(16.0f) + ((this.isRoundFrames ? this.frameWidth / 2 : this.frameWidth) * offset);
                    int y = AndroidUtilities.dp(2.0f);
                    if (this.isRoundFrames) {
                        this.rect2.set(x, y, AndroidUtilities.dp(28.0f) + x, AndroidUtilities.dp(28.0f) + y);
                        canvas.drawBitmap(bitmap, this.rect1, this.rect2, (Paint) null);
                    } else {
                        canvas.drawBitmap(bitmap, x, y, (Paint) null);
                    }
                }
                offset++;
            }
        }
        int top = AndroidUtilities.dp(2.0f);
        canvas.drawRect(AndroidUtilities.dp(16.0f), top, startX, getMeasuredHeight() - top, this.paint2);
        canvas.drawRect(AndroidUtilities.dp(4.0f) + endX, top, AndroidUtilities.dp(16.0f) + width + AndroidUtilities.dp(4.0f), getMeasuredHeight() - top, this.paint2);
        canvas.drawRect(startX, 0.0f, AndroidUtilities.dp(2.0f) + startX, getMeasuredHeight(), this.paint);
        canvas.drawRect(AndroidUtilities.dp(2.0f) + endX, 0.0f, AndroidUtilities.dp(4.0f) + endX, getMeasuredHeight(), this.paint);
        canvas.drawRect(AndroidUtilities.dp(2.0f) + startX, 0.0f, AndroidUtilities.dp(4.0f) + endX, top, this.paint);
        canvas.drawRect(AndroidUtilities.dp(2.0f) + startX, getMeasuredHeight() - top, AndroidUtilities.dp(4.0f) + endX, getMeasuredHeight(), this.paint);
        canvas.restore();
        canvas.drawCircle(startX, getMeasuredHeight() / 2, AndroidUtilities.dp(7.0f), this.paint);
        canvas.drawCircle(AndroidUtilities.dp(4.0f) + endX, getMeasuredHeight() / 2, AndroidUtilities.dp(7.0f), this.paint);
    }
}
