package im.uwrkaxlmjj.ui.components.paint.views;

import android.content.Context;
import android.graphics.Paint;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.components.Point;
import im.uwrkaxlmjj.ui.components.Rect;
import java.util.UUID;

/* JADX INFO: loaded from: classes5.dex */
public class EntityView extends FrameLayout {
    private boolean announcedSelection;
    private EntityViewDelegate delegate;
    private GestureDetector gestureDetector;
    private boolean hasPanned;
    private boolean hasReleased;
    private boolean hasTransformed;
    private int offsetX;
    private int offsetY;
    protected Point position;
    private float previousLocationX;
    private float previousLocationY;
    private boolean recognizedLongPress;
    protected SelectionView selectionView;
    private UUID uuid;

    public interface EntityViewDelegate {
        boolean allowInteraction(EntityView entityView);

        boolean onEntityLongClicked(EntityView entityView);

        boolean onEntitySelected(EntityView entityView);
    }

    public EntityView(Context context, Point pos) {
        super(context);
        this.hasPanned = false;
        this.hasReleased = false;
        this.hasTransformed = false;
        this.announcedSelection = false;
        this.recognizedLongPress = false;
        this.position = new Point();
        this.uuid = UUID.randomUUID();
        this.position = pos;
        this.gestureDetector = new GestureDetector(context, new GestureDetector.SimpleOnGestureListener() { // from class: im.uwrkaxlmjj.ui.components.paint.views.EntityView.1
            @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
            public void onLongPress(MotionEvent e) {
                if (!EntityView.this.hasPanned && !EntityView.this.hasTransformed && !EntityView.this.hasReleased) {
                    EntityView.this.recognizedLongPress = true;
                    if (EntityView.this.delegate != null) {
                        EntityView.this.performHapticFeedback(0);
                        EntityView.this.delegate.onEntityLongClicked(EntityView.this);
                    }
                }
            }
        });
    }

    public UUID getUUID() {
        return this.uuid;
    }

    public Point getPosition() {
        return this.position;
    }

    public void setPosition(Point value) {
        this.position = value;
        updatePosition();
    }

    public float getScale() {
        return getScaleX();
    }

    public void setScale(float scale) {
        setScaleX(scale);
        setScaleY(scale);
    }

    public void setDelegate(EntityViewDelegate entityViewDelegate) {
        this.delegate = entityViewDelegate;
    }

    public void setOffset(int x, int y) {
        this.offsetX = x;
        this.offsetY = y;
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        return this.delegate.allowInteraction(this);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onTouchMove(float x, float y) {
        float scale = ((View) getParent()).getScaleX();
        Point translation = new Point((x - this.previousLocationX) / scale, (y - this.previousLocationY) / scale);
        float distance = (float) Math.hypot(translation.x, translation.y);
        float minDistance = this.hasPanned ? 6.0f : 16.0f;
        if (distance > minDistance) {
            pan(translation);
            this.previousLocationX = x;
            this.previousLocationY = y;
            this.hasPanned = true;
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onTouchUp() {
        EntityViewDelegate entityViewDelegate;
        if (!this.recognizedLongPress && !this.hasPanned && !this.hasTransformed && !this.announcedSelection && (entityViewDelegate = this.delegate) != null) {
            entityViewDelegate.onEntitySelected(this);
        }
        this.recognizedLongPress = false;
        this.hasPanned = false;
        this.hasTransformed = false;
        this.hasReleased = true;
        this.announcedSelection = false;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0034  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0039  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r8) {
        /*
            r7 = this;
            int r0 = r8.getPointerCount()
            r1 = 0
            r2 = 1
            if (r0 > r2) goto L56
            im.uwrkaxlmjj.ui.components.paint.views.EntityView$EntityViewDelegate r0 = r7.delegate
            boolean r0 = r0.allowInteraction(r7)
            if (r0 != 0) goto L11
            goto L56
        L11:
            float r0 = r8.getRawX()
            float r3 = r8.getRawY()
            int r4 = r8.getActionMasked()
            r5 = 0
            if (r4 == 0) goto L39
            if (r4 == r2) goto L34
            r6 = 2
            if (r4 == r6) goto L2f
            r6 = 3
            if (r4 == r6) goto L34
            r6 = 5
            if (r4 == r6) goto L39
            r1 = 6
            if (r4 == r1) goto L34
            goto L50
        L2f:
            boolean r5 = r7.onTouchMove(r0, r3)
            goto L50
        L34:
            r7.onTouchUp()
            r5 = 1
            goto L50
        L39:
            boolean r6 = r7.isSelected()
            if (r6 != 0) goto L48
            im.uwrkaxlmjj.ui.components.paint.views.EntityView$EntityViewDelegate r6 = r7.delegate
            if (r6 == 0) goto L48
            r6.onEntitySelected(r7)
            r7.announcedSelection = r2
        L48:
            r7.previousLocationX = r0
            r7.previousLocationY = r3
            r5 = 1
            r7.hasReleased = r1
        L50:
            android.view.GestureDetector r1 = r7.gestureDetector
            r1.onTouchEvent(r8)
            return r5
        L56:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.paint.views.EntityView.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public void pan(Point translation) {
        this.position.x += translation.x;
        this.position.y += translation.y;
        updatePosition();
    }

    protected void updatePosition() {
        float halfWidth = getWidth() / 2.0f;
        float halfHeight = getHeight() / 2.0f;
        setX(this.position.x - halfWidth);
        setY(this.position.y - halfHeight);
        updateSelectionView();
    }

    public void scale(float scale) {
        float newScale = Math.max(getScale() * scale, 0.1f);
        setScale(newScale);
        updateSelectionView();
    }

    public void rotate(float angle) {
        setRotation(angle);
        updateSelectionView();
    }

    protected Rect getSelectionBounds() {
        return new Rect(0.0f, 0.0f, 0.0f, 0.0f);
    }

    @Override // android.view.View
    public boolean isSelected() {
        return this.selectionView != null;
    }

    protected SelectionView createSelectionView() {
        return null;
    }

    public void updateSelectionView() {
        SelectionView selectionView = this.selectionView;
        if (selectionView != null) {
            selectionView.updatePosition();
        }
    }

    public void select(ViewGroup selectionContainer) {
        SelectionView selectionView = createSelectionView();
        this.selectionView = selectionView;
        selectionContainer.addView(selectionView);
        selectionView.updatePosition();
    }

    public void deselect() {
        SelectionView selectionView = this.selectionView;
        if (selectionView == null) {
            return;
        }
        if (selectionView.getParent() != null) {
            ((ViewGroup) this.selectionView.getParent()).removeView(this.selectionView);
        }
        this.selectionView = null;
    }

    public void setSelectionVisibility(boolean visible) {
        SelectionView selectionView = this.selectionView;
        if (selectionView == null) {
            return;
        }
        selectionView.setVisibility(visible ? 0 : 8);
    }

    public class SelectionView extends FrameLayout {
        public static final int SELECTION_LEFT_HANDLE = 1;
        public static final int SELECTION_RIGHT_HANDLE = 2;
        public static final int SELECTION_WHOLE_HANDLE = 3;
        private int currentHandle;
        protected Paint dotPaint;
        protected Paint dotStrokePaint;
        protected Paint paint;

        public SelectionView(Context context) {
            super(context);
            this.paint = new Paint(1);
            this.dotPaint = new Paint(1);
            this.dotStrokePaint = new Paint(1);
            setWillNotDraw(false);
            this.paint.setColor(-1);
            this.dotPaint.setColor(-12793105);
            this.dotStrokePaint.setColor(-1);
            this.dotStrokePaint.setStyle(Paint.Style.STROKE);
            this.dotStrokePaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
        }

        protected void updatePosition() {
            Rect bounds = EntityView.this.getSelectionBounds();
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) getLayoutParams();
            layoutParams.leftMargin = ((int) bounds.x) + EntityView.this.offsetX;
            layoutParams.topMargin = ((int) bounds.y) + EntityView.this.offsetY;
            layoutParams.width = (int) bounds.width;
            layoutParams.height = (int) bounds.height;
            setLayoutParams(layoutParams);
            setRotation(EntityView.this.getRotation());
        }

        protected int pointInsideHandle(float x, float y) {
            return 0;
        }

        /* JADX WARN: Removed duplicated region for block: B:42:0x0164  */
        /* JADX WARN: Removed duplicated region for block: B:43:0x0170  */
        @Override // android.view.View
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean onTouchEvent(android.view.MotionEvent r19) {
            /*
                Method dump skipped, instruction units count: 371
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.paint.views.EntityView.SelectionView.onTouchEvent(android.view.MotionEvent):boolean");
        }
    }
}
