package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import android.os.Looper;
import android.util.SparseArray;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import com.google.android.gms.vision.Frame;
import com.google.android.gms.vision.face.Face;
import com.google.android.gms.vision.face.FaceDetector;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.Bitmaps;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.StickerMasksView;
import im.uwrkaxlmjj.ui.components.paint.Brush;
import im.uwrkaxlmjj.ui.components.paint.Painting;
import im.uwrkaxlmjj.ui.components.paint.PhotoFace;
import im.uwrkaxlmjj.ui.components.paint.RenderView;
import im.uwrkaxlmjj.ui.components.paint.Swatch;
import im.uwrkaxlmjj.ui.components.paint.UndoStore;
import im.uwrkaxlmjj.ui.components.paint.views.ColorPicker;
import im.uwrkaxlmjj.ui.components.paint.views.EditTextOutline;
import im.uwrkaxlmjj.ui.components.paint.views.EntitiesContainerView;
import im.uwrkaxlmjj.ui.components.paint.views.EntityView;
import im.uwrkaxlmjj.ui.components.paint.views.StickerView;
import im.uwrkaxlmjj.ui.components.paint.views.TextPaintView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoPaintView extends FrameLayout implements EntityView.EntityViewDelegate {
    private static final int gallery_menu_done = 1;
    private Bitmap bitmapToEdit;
    private Brush[] brushes;
    private TextView cancelTextView;
    private im.uwrkaxlmjj.ui.components.paint.views.ColorPicker colorPicker;
    private Animator colorPickerAnimator;
    int currentBrush;
    private EntityView currentEntityView;
    private FrameLayout curtainView;
    private FrameLayout dimView;
    private TextView doneTextView;
    private Point editedTextPosition;
    private float editedTextRotation;
    private float editedTextScale;
    private boolean editingText;
    private EntitiesContainerView entitiesView;
    private ArrayList<PhotoFace> faces;
    private String initialText;
    private int orientation;
    private ImageView paintButton;
    private Size paintingSize;
    private boolean pickingSticker;
    private ActionBarPopupWindow.ActionBarPopupWindowLayout popupLayout;
    private android.graphics.Rect popupRect;
    private ActionBarPopupWindow popupWindow;
    private DispatchQueue queue;
    private RenderView renderView;
    private boolean selectedStroke;
    private FrameLayout selectionContainerView;
    private StickerMasksView stickersView;
    private FrameLayout textDimView;
    private FrameLayout toolsView;
    private UndoStore undoStore;

    public PhotoPaintView(Context context, Bitmap bitmap, int rotation) {
        super(context);
        this.brushes = new Brush[]{new Brush.Radial(), new Brush.Elliptical(), new Brush.Neon()};
        this.selectedStroke = true;
        this.queue = new DispatchQueue("Paint");
        this.bitmapToEdit = bitmap;
        this.orientation = rotation;
        UndoStore undoStore = new UndoStore();
        this.undoStore = undoStore;
        undoStore.setDelegate(new UndoStore.UndoStoreDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$gd4iVCqzlNYMgkGvL85_f53tA0M
            @Override // im.uwrkaxlmjj.ui.components.paint.UndoStore.UndoStoreDelegate
            public final void historyChanged() {
                this.f$0.lambda$new$0$PhotoPaintView();
            }
        });
        FrameLayout frameLayout = new FrameLayout(context);
        this.curtainView = frameLayout;
        frameLayout.setBackgroundColor(-16777216);
        this.curtainView.setVisibility(4);
        addView(this.curtainView);
        RenderView renderView = new RenderView(context, new Painting(getPaintingSize()), bitmap, this.orientation);
        this.renderView = renderView;
        renderView.setDelegate(new RenderView.RenderViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.1
            @Override // im.uwrkaxlmjj.ui.components.paint.RenderView.RenderViewDelegate
            public void onBeganDrawing() {
                if (PhotoPaintView.this.currentEntityView != null) {
                    PhotoPaintView.this.selectEntity(null);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.RenderView.RenderViewDelegate
            public void onFinishedDrawing(boolean moved) {
                PhotoPaintView.this.colorPicker.setUndoEnabled(PhotoPaintView.this.undoStore.canUndo());
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.RenderView.RenderViewDelegate
            public boolean shouldDraw() {
                boolean draw = PhotoPaintView.this.currentEntityView == null;
                if (!draw) {
                    PhotoPaintView.this.selectEntity(null);
                }
                return draw;
            }
        });
        this.renderView.setUndoStore(this.undoStore);
        this.renderView.setQueue(this.queue);
        this.renderView.setVisibility(4);
        this.renderView.setBrush(this.brushes[0]);
        addView(this.renderView, LayoutHelper.createFrame(-1, -1, 51));
        EntitiesContainerView entitiesContainerView = new EntitiesContainerView(context, new EntitiesContainerView.EntitiesContainerViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.2
            @Override // im.uwrkaxlmjj.ui.components.paint.views.EntitiesContainerView.EntitiesContainerViewDelegate
            public boolean shouldReceiveTouches() {
                return PhotoPaintView.this.textDimView.getVisibility() != 0;
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.views.EntitiesContainerView.EntitiesContainerViewDelegate
            public EntityView onSelectedEntityRequest() {
                return PhotoPaintView.this.currentEntityView;
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.views.EntitiesContainerView.EntitiesContainerViewDelegate
            public void onEntityDeselect() {
                PhotoPaintView.this.selectEntity(null);
            }
        });
        this.entitiesView = entitiesContainerView;
        entitiesContainerView.setPivotX(0.0f);
        this.entitiesView.setPivotY(0.0f);
        addView(this.entitiesView);
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.dimView = frameLayout2;
        frameLayout2.setAlpha(0.0f);
        this.dimView.setBackgroundColor(1711276032);
        this.dimView.setVisibility(8);
        addView(this.dimView);
        FrameLayout frameLayout3 = new FrameLayout(context);
        this.textDimView = frameLayout3;
        frameLayout3.setAlpha(0.0f);
        this.textDimView.setBackgroundColor(1711276032);
        this.textDimView.setVisibility(8);
        this.textDimView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$mOLx_l_2XoP0PPgZXjCldUt0Yjw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$1$PhotoPaintView(view);
            }
        });
        FrameLayout frameLayout4 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.3
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return false;
            }
        };
        this.selectionContainerView = frameLayout4;
        addView(frameLayout4);
        im.uwrkaxlmjj.ui.components.paint.views.ColorPicker colorPicker = new im.uwrkaxlmjj.ui.components.paint.views.ColorPicker(context);
        this.colorPicker = colorPicker;
        addView(colorPicker);
        this.colorPicker.setDelegate(new ColorPicker.ColorPickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.4
            @Override // im.uwrkaxlmjj.ui.components.paint.views.ColorPicker.ColorPickerDelegate
            public void onBeganColorPicking() {
                if (!(PhotoPaintView.this.currentEntityView instanceof TextPaintView)) {
                    PhotoPaintView.this.setDimVisibility(true);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.views.ColorPicker.ColorPickerDelegate
            public void onColorValueChanged() {
                PhotoPaintView photoPaintView = PhotoPaintView.this;
                photoPaintView.setCurrentSwatch(photoPaintView.colorPicker.getSwatch(), false);
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.views.ColorPicker.ColorPickerDelegate
            public void onFinishedColorPicking() {
                PhotoPaintView photoPaintView = PhotoPaintView.this;
                photoPaintView.setCurrentSwatch(photoPaintView.colorPicker.getSwatch(), false);
                if (!(PhotoPaintView.this.currentEntityView instanceof TextPaintView)) {
                    PhotoPaintView.this.setDimVisibility(false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.views.ColorPicker.ColorPickerDelegate
            public void onSettingsPressed() {
                if (PhotoPaintView.this.currentEntityView != null) {
                    if (PhotoPaintView.this.currentEntityView instanceof StickerView) {
                        PhotoPaintView.this.mirrorSticker();
                        return;
                    } else {
                        if (PhotoPaintView.this.currentEntityView instanceof TextPaintView) {
                            PhotoPaintView.this.showTextSettings();
                            return;
                        }
                        return;
                    }
                }
                PhotoPaintView.this.showBrushSettings();
            }

            @Override // im.uwrkaxlmjj.ui.components.paint.views.ColorPicker.ColorPickerDelegate
            public void onUndoPressed() {
                PhotoPaintView.this.undoStore.undo();
            }
        });
        FrameLayout frameLayout5 = new FrameLayout(context);
        this.toolsView = frameLayout5;
        frameLayout5.setBackgroundColor(-16777216);
        addView(this.toolsView, LayoutHelper.createFrame(-1, 48, 83));
        TextView textView = new TextView(context);
        this.cancelTextView = textView;
        textView.setTextSize(1, 14.0f);
        this.cancelTextView.setTextColor(-1);
        this.cancelTextView.setGravity(17);
        this.cancelTextView.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_PICKER_SELECTOR_COLOR, 0));
        this.cancelTextView.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        this.cancelTextView.setText(LocaleController.getString("Cancel", R.string.Cancel).toUpperCase());
        this.cancelTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.toolsView.addView(this.cancelTextView, LayoutHelper.createFrame(-2, -1, 51));
        TextView textView2 = new TextView(context);
        this.doneTextView = textView2;
        textView2.setTextSize(1, 14.0f);
        this.doneTextView.setTextColor(-11420173);
        this.doneTextView.setGravity(17);
        this.doneTextView.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_PICKER_SELECTOR_COLOR, 0));
        this.doneTextView.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        this.doneTextView.setText(LocaleController.getString("Done", R.string.Done).toUpperCase());
        this.doneTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.toolsView.addView(this.doneTextView, LayoutHelper.createFrame(-2, -1, 53));
        ImageView imageView = new ImageView(context);
        this.paintButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.paintButton.setImageResource(R.drawable.photo_paint);
        this.paintButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.toolsView.addView(this.paintButton, LayoutHelper.createFrame(54.0f, -1.0f, 17, 0.0f, 0.0f, 56.0f, 0.0f));
        this.paintButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$0vIZ_odDEumZzSls3C2BJI8CMyo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$2$PhotoPaintView(view);
            }
        });
        ImageView stickerButton = new ImageView(context);
        stickerButton.setScaleType(ImageView.ScaleType.CENTER);
        stickerButton.setImageResource(R.drawable.photo_sticker);
        stickerButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.toolsView.addView(stickerButton, LayoutHelper.createFrame(54, -1, 17));
        stickerButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$RcWmczGid7FfHpPwzE7UCKrdZZw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$3$PhotoPaintView(view);
            }
        });
        ImageView textButton = new ImageView(context);
        textButton.setScaleType(ImageView.ScaleType.CENTER);
        textButton.setImageResource(R.drawable.photo_paint_text);
        textButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.toolsView.addView(textButton, LayoutHelper.createFrame(54.0f, -1.0f, 17, 56.0f, 0.0f, 0.0f, 0.0f));
        textButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$ukHZvVdr9H7FlgDlT3qIbW01TQ0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$4$PhotoPaintView(view);
            }
        });
        this.colorPicker.setUndoEnabled(false);
        setCurrentSwatch(this.colorPicker.getSwatch(), false);
        updateSettingsButton();
    }

    public /* synthetic */ void lambda$new$0$PhotoPaintView() {
        this.colorPicker.setUndoEnabled(this.undoStore.canUndo());
    }

    public /* synthetic */ void lambda$new$1$PhotoPaintView(View v) {
        closeTextEnter(true);
    }

    public /* synthetic */ void lambda$new$2$PhotoPaintView(View v) {
        selectEntity(null);
    }

    public /* synthetic */ void lambda$new$3$PhotoPaintView(View v) {
        openStickersView();
    }

    public /* synthetic */ void lambda$new$4$PhotoPaintView(View v) {
        createText();
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (this.currentEntityView != null) {
            if (this.editingText) {
                closeTextEnter(true);
            } else {
                selectEntity(null);
            }
        }
        return true;
    }

    private Size getPaintingSize() {
        Size size = this.paintingSize;
        if (size != null) {
            return size;
        }
        float width = isSidewardOrientation() ? this.bitmapToEdit.getHeight() : this.bitmapToEdit.getWidth();
        float height = isSidewardOrientation() ? this.bitmapToEdit.getWidth() : this.bitmapToEdit.getHeight();
        Size size2 = new Size(width, height);
        size2.width = 1280.0f;
        size2.height = (float) Math.floor((size2.width * height) / width);
        if (size2.height > 1280.0f) {
            size2.height = 1280.0f;
            size2.width = (float) Math.floor((size2.height * width) / height);
        }
        this.paintingSize = size2;
        return size2;
    }

    private boolean isSidewardOrientation() {
        int i = this.orientation;
        return i % 360 == 90 || i % 360 == 270;
    }

    private void updateSettingsButton() {
        int resource = R.drawable.photo_paint_brush;
        EntityView entityView = this.currentEntityView;
        if (entityView != null) {
            if (entityView instanceof StickerView) {
                resource = R.drawable.photo_flip;
            } else if (entityView instanceof TextPaintView) {
                resource = R.drawable.photo_outline;
            }
            this.paintButton.setImageResource(R.drawable.photo_paint);
            this.paintButton.setColorFilter((ColorFilter) null);
        } else {
            this.paintButton.setColorFilter(new PorterDuffColorFilter(-11420173, PorterDuff.Mode.MULTIPLY));
            this.paintButton.setImageResource(R.drawable.photo_paint);
        }
        this.colorPicker.setSettingsButtonImage(resource);
    }

    public void init() {
        this.renderView.setVisibility(0);
        detectFaces();
    }

    public void shutdown() {
        this.renderView.shutdown();
        this.entitiesView.setVisibility(8);
        this.selectionContainerView.setVisibility(8);
        this.queue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$CmeDmSANqiVk9ZNpZu17U49RgIA
            @Override // java.lang.Runnable
            public final void run() {
                PhotoPaintView.lambda$shutdown$5();
            }
        });
    }

    static /* synthetic */ void lambda$shutdown$5() {
        Looper looper = Looper.myLooper();
        if (looper != null) {
            looper.quit();
        }
    }

    public FrameLayout getToolsView() {
        return this.toolsView;
    }

    public TextView getDoneTextView() {
        return this.doneTextView;
    }

    public TextView getCancelTextView() {
        return this.cancelTextView;
    }

    public im.uwrkaxlmjj.ui.components.paint.views.ColorPicker getColorPicker() {
        return this.colorPicker;
    }

    private boolean hasChanges() {
        return this.undoStore.canUndo() || this.entitiesView.entitiesCount() > 0;
    }

    public Bitmap getBitmap() {
        Bitmap bitmap = this.renderView.getResultBitmap();
        if (bitmap != null && this.entitiesView.entitiesCount() > 0) {
            Canvas canvas = new Canvas(bitmap);
            for (int i = 0; i < this.entitiesView.getChildCount(); i++) {
                View v = this.entitiesView.getChildAt(i);
                canvas.save();
                if (v instanceof EntityView) {
                    EntityView entity = (EntityView) v;
                    canvas.translate(entity.getPosition().x, entity.getPosition().y);
                    canvas.scale(v.getScaleX(), v.getScaleY());
                    canvas.rotate(v.getRotation());
                    canvas.translate((-entity.getWidth()) / 2, (-entity.getHeight()) / 2);
                    if (v instanceof TextPaintView) {
                        Bitmap b = Bitmaps.createBitmap(v.getWidth(), v.getHeight(), Bitmap.Config.ARGB_8888);
                        Canvas c = new Canvas(b);
                        v.draw(c);
                        canvas.drawBitmap(b, (android.graphics.Rect) null, new android.graphics.Rect(0, 0, b.getWidth(), b.getHeight()), (Paint) null);
                        try {
                            c.setBitmap(null);
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                        b.recycle();
                    } else {
                        v.draw(canvas);
                    }
                }
                canvas.restore();
            }
        }
        return bitmap;
    }

    public void maybeShowDismissalAlert(PhotoViewer photoViewer, Activity parentActivity, final Runnable okRunnable) {
        if (this.editingText) {
            closeTextEnter(false);
            return;
        }
        if (this.pickingSticker) {
            closeStickersView();
            return;
        }
        if (hasChanges()) {
            if (parentActivity == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(parentActivity);
            builder.setMessage(LocaleController.getString("DiscardChanges", R.string.DiscardChanges));
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$b-Q6NgT_GM0-GDxga3XqIGDjZJk
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    okRunnable.run();
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            photoViewer.showAlertDialog(builder);
            return;
        }
        okRunnable.run();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setCurrentSwatch(Swatch swatch, boolean updateInterface) {
        this.renderView.setColor(swatch.color);
        this.renderView.setBrushSize(swatch.brushWeight);
        if (updateInterface) {
            this.colorPicker.setSwatch(swatch);
        }
        EntityView entityView = this.currentEntityView;
        if (entityView instanceof TextPaintView) {
            ((TextPaintView) entityView).setSwatch(swatch);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setDimVisibility(final boolean visible) {
        Animator animator;
        if (!visible) {
            animator = ObjectAnimator.ofFloat(this.dimView, "alpha", 1.0f, 0.0f);
        } else {
            this.dimView.setVisibility(0);
            animator = ObjectAnimator.ofFloat(this.dimView, "alpha", 0.0f, 1.0f);
        }
        animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.5
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (!visible) {
                    PhotoPaintView.this.dimView.setVisibility(8);
                }
            }
        });
        animator.setDuration(200L);
        animator.start();
    }

    private void setTextDimVisibility(final boolean visible, EntityView view) {
        Animator animator;
        if (visible && view != null) {
            ViewGroup parent = (ViewGroup) view.getParent();
            if (this.textDimView.getParent() != null) {
                ((EntitiesContainerView) this.textDimView.getParent()).removeView(this.textDimView);
            }
            parent.addView(this.textDimView, parent.indexOfChild(view));
        }
        view.setSelectionVisibility(!visible);
        if (!visible) {
            animator = ObjectAnimator.ofFloat(this.textDimView, "alpha", 1.0f, 0.0f);
        } else {
            this.textDimView.setVisibility(0);
            animator = ObjectAnimator.ofFloat(this.textDimView, "alpha", 0.0f, 1.0f);
        }
        animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.6
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (!visible) {
                    PhotoPaintView.this.textDimView.setVisibility(8);
                    if (PhotoPaintView.this.textDimView.getParent() != null) {
                        ((EntitiesContainerView) PhotoPaintView.this.textDimView.getParent()).removeView(PhotoPaintView.this.textDimView);
                    }
                }
            }
        });
        animator.setDuration(200L);
        animator.start();
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        float bitmapW;
        float bitmapH;
        int width = View.MeasureSpec.getSize(widthMeasureSpec);
        int height = View.MeasureSpec.getSize(heightMeasureSpec);
        setMeasuredDimension(width, height);
        int fullHeight = AndroidUtilities.displaySize.y - ActionBar.getCurrentActionBarHeight();
        int maxHeight = fullHeight - AndroidUtilities.dp(48.0f);
        if (this.bitmapToEdit != null) {
            bitmapW = isSidewardOrientation() ? this.bitmapToEdit.getHeight() : this.bitmapToEdit.getWidth();
            bitmapH = isSidewardOrientation() ? this.bitmapToEdit.getWidth() : this.bitmapToEdit.getHeight();
        } else {
            bitmapW = width;
            bitmapH = (height - ActionBar.getCurrentActionBarHeight()) - AndroidUtilities.dp(48.0f);
        }
        float renderWidth = width;
        float renderHeight = (float) Math.floor((renderWidth * bitmapH) / bitmapW);
        if (renderHeight > maxHeight) {
            renderHeight = maxHeight;
            renderWidth = (float) Math.floor((renderHeight * bitmapW) / bitmapH);
        }
        this.renderView.measure(View.MeasureSpec.makeMeasureSpec((int) renderWidth, 1073741824), View.MeasureSpec.makeMeasureSpec((int) renderHeight, 1073741824));
        this.entitiesView.measure(View.MeasureSpec.makeMeasureSpec((int) this.paintingSize.width, 1073741824), View.MeasureSpec.makeMeasureSpec((int) this.paintingSize.height, 1073741824));
        this.dimView.measure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(maxHeight, Integer.MIN_VALUE));
        this.selectionContainerView.measure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(maxHeight, 1073741824));
        this.colorPicker.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(maxHeight, 1073741824));
        this.toolsView.measure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), 1073741824));
        StickerMasksView stickerMasksView = this.stickersView;
        if (stickerMasksView != null) {
            stickerMasksView.measure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.displaySize.y, 1073741824));
        }
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        float bitmapW;
        float bitmapH;
        int width = right - left;
        int height = bottom - top;
        int status = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
        int actionBarHeight = ActionBar.getCurrentActionBarHeight();
        int actionBarHeight2 = ActionBar.getCurrentActionBarHeight() + status;
        int maxHeight = (AndroidUtilities.displaySize.y - actionBarHeight) - AndroidUtilities.dp(48.0f);
        if (this.bitmapToEdit != null) {
            bitmapW = isSidewardOrientation() ? this.bitmapToEdit.getHeight() : this.bitmapToEdit.getWidth();
            bitmapH = isSidewardOrientation() ? this.bitmapToEdit.getWidth() : this.bitmapToEdit.getHeight();
        } else {
            bitmapW = width;
            bitmapH = (height - actionBarHeight) - AndroidUtilities.dp(48.0f);
        }
        float renderWidth = width;
        float renderHeight = (float) Math.floor((renderWidth * bitmapH) / bitmapW);
        if (renderHeight > maxHeight) {
            float renderHeight2 = maxHeight;
            renderWidth = (float) Math.floor((renderHeight2 * bitmapW) / bitmapH);
        }
        int x = (int) Math.ceil((width - this.renderView.getMeasuredWidth()) / 2);
        int y = ((((((height - actionBarHeight2) - AndroidUtilities.dp(48.0f)) - this.renderView.getMeasuredHeight()) / 2) + actionBarHeight2) - ActionBar.getCurrentActionBarHeight()) + AndroidUtilities.dp(8.0f);
        RenderView renderView = this.renderView;
        renderView.layout(x, y, renderView.getMeasuredWidth() + x, this.renderView.getMeasuredHeight() + y);
        float scale = renderWidth / this.paintingSize.width;
        this.entitiesView.setScaleX(scale);
        this.entitiesView.setScaleY(scale);
        EntitiesContainerView entitiesContainerView = this.entitiesView;
        entitiesContainerView.layout(x, y, entitiesContainerView.getMeasuredWidth() + x, this.entitiesView.getMeasuredHeight() + y);
        FrameLayout frameLayout = this.dimView;
        frameLayout.layout(0, status, frameLayout.getMeasuredWidth(), this.dimView.getMeasuredHeight() + status);
        FrameLayout frameLayout2 = this.selectionContainerView;
        frameLayout2.layout(0, status, frameLayout2.getMeasuredWidth(), this.selectionContainerView.getMeasuredHeight() + status);
        im.uwrkaxlmjj.ui.components.paint.views.ColorPicker colorPicker = this.colorPicker;
        colorPicker.layout(0, actionBarHeight2, colorPicker.getMeasuredWidth(), this.colorPicker.getMeasuredHeight() + actionBarHeight2);
        FrameLayout frameLayout3 = this.toolsView;
        frameLayout3.layout(0, height - frameLayout3.getMeasuredHeight(), this.toolsView.getMeasuredWidth(), height);
        this.curtainView.layout(0, 0, width, maxHeight);
        StickerMasksView stickerMasksView = this.stickersView;
        if (stickerMasksView != null) {
            stickerMasksView.layout(0, status, stickerMasksView.getMeasuredWidth(), this.stickersView.getMeasuredHeight() + status);
        }
        EntityView entityView = this.currentEntityView;
        if (entityView != null) {
            entityView.updateSelectionView();
            this.currentEntityView.setOffset(this.entitiesView.getLeft() - this.selectionContainerView.getLeft(), this.entitiesView.getTop() - this.selectionContainerView.getTop());
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView.EntityViewDelegate
    public boolean onEntitySelected(EntityView entityView) {
        return selectEntity(entityView);
    }

    @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView.EntityViewDelegate
    public boolean onEntityLongClicked(EntityView entityView) {
        showMenuForEntity(entityView);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.components.paint.views.EntityView.EntityViewDelegate
    public boolean allowInteraction(EntityView entityView) {
        return !this.editingText;
    }

    private Point centerPositionForEntity() {
        Size paintingSize = getPaintingSize();
        return new Point(paintingSize.width / 2.0f, paintingSize.height / 2.0f);
    }

    private Point startPositionRelativeToEntity(EntityView entityView) {
        if (entityView != null) {
            Point position = entityView.getPosition();
            return new Point(position.x + 200.0f, position.y + 200.0f);
        }
        Point position2 = centerPositionForEntity();
        while (true) {
            boolean occupied = false;
            for (int index = 0; index < this.entitiesView.getChildCount(); index++) {
                View view = this.entitiesView.getChildAt(index);
                if (view instanceof EntityView) {
                    Point location = ((EntityView) view).getPosition();
                    float distance = (float) Math.sqrt(Math.pow(location.x - position2.x, 2.0d) + Math.pow(location.y - position2.y, 2.0d));
                    if (distance < 100.0f) {
                        occupied = true;
                    }
                }
            }
            if (occupied) {
                position2 = new Point(position2.x + 200.0f, position2.y + 200.0f);
            } else {
                return position2;
            }
        }
    }

    public ArrayList<TLRPC.InputDocument> getMasks() {
        ArrayList<TLRPC.InputDocument> result = null;
        int count = this.entitiesView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.entitiesView.getChildAt(a);
            if (child instanceof StickerView) {
                TLRPC.Document document = ((StickerView) child).getSticker();
                if (result == null) {
                    result = new ArrayList<>();
                }
                TLRPC.TL_inputDocument inputDocument = new TLRPC.TL_inputDocument();
                inputDocument.id = document.id;
                inputDocument.access_hash = document.access_hash;
                inputDocument.file_reference = document.file_reference;
                if (inputDocument.file_reference == null) {
                    inputDocument.file_reference = new byte[0];
                }
                result.add(inputDocument);
            }
        }
        return result;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean selectEntity(EntityView entityView) {
        boolean changed = false;
        EntityView entityView2 = this.currentEntityView;
        if (entityView2 != null) {
            if (entityView2 == entityView) {
                if (!this.editingText) {
                    showMenuForEntity(entityView2);
                }
                return true;
            }
            entityView2.deselect();
            changed = true;
        }
        this.currentEntityView = entityView;
        if (entityView != null) {
            entityView.select(this.selectionContainerView);
            this.entitiesView.bringViewToFront(this.currentEntityView);
            EntityView entityView3 = this.currentEntityView;
            if (entityView3 instanceof TextPaintView) {
                setCurrentSwatch(((TextPaintView) entityView3).getSwatch(), true);
            }
            changed = true;
        }
        updateSettingsButton();
        return changed;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: removeEntity, reason: merged with bridge method [inline-methods] */
    public void lambda$registerRemovalUndo$7$PhotoPaintView(EntityView entityView) {
        EntityView entityView2 = this.currentEntityView;
        if (entityView == entityView2) {
            entityView2.deselect();
            if (this.editingText) {
                closeTextEnter(false);
            }
            this.currentEntityView = null;
            updateSettingsButton();
        }
        this.entitiesView.removeView(entityView);
        this.undoStore.unregisterUndo(entityView.getUUID());
    }

    private void duplicateSelectedEntity() {
        EntityView entityView = this.currentEntityView;
        if (entityView == null) {
            return;
        }
        EntityView entityView2 = null;
        Point position = startPositionRelativeToEntity(entityView);
        EntityView entityView3 = this.currentEntityView;
        if (entityView3 instanceof StickerView) {
            EntityView newStickerView = new StickerView(getContext(), (StickerView) this.currentEntityView, position);
            newStickerView.setDelegate(this);
            this.entitiesView.addView(newStickerView);
            entityView2 = newStickerView;
        } else if (entityView3 instanceof TextPaintView) {
            TextPaintView newTextPaintView = new TextPaintView(getContext(), (TextPaintView) this.currentEntityView, position);
            newTextPaintView.setDelegate(this);
            newTextPaintView.setMaxWidth((int) (getPaintingSize().width - 20.0f));
            this.entitiesView.addView(newTextPaintView, LayoutHelper.createFrame(-2, -2.0f));
            entityView2 = newTextPaintView;
        }
        registerRemovalUndo(entityView2);
        selectEntity(entityView2);
        updateSettingsButton();
    }

    private void openStickersView() {
        StickerMasksView stickerMasksView = this.stickersView;
        if (stickerMasksView != null && stickerMasksView.getVisibility() == 0) {
            return;
        }
        this.pickingSticker = true;
        if (this.stickersView == null) {
            StickerMasksView stickerMasksView2 = new StickerMasksView(getContext());
            this.stickersView = stickerMasksView2;
            stickerMasksView2.setListener(new StickerMasksView.Listener() { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.7
                @Override // im.uwrkaxlmjj.ui.components.StickerMasksView.Listener
                public void onStickerSelected(Object parentObject, TLRPC.Document sticker) {
                    PhotoPaintView.this.closeStickersView();
                    PhotoPaintView.this.createSticker(parentObject, sticker);
                }

                @Override // im.uwrkaxlmjj.ui.components.StickerMasksView.Listener
                public void onTypeChanged() {
                }
            });
            addView(this.stickersView, LayoutHelper.createFrame(-1, -1, 51));
        }
        this.stickersView.setVisibility(0);
        Animator a = ObjectAnimator.ofFloat(this.stickersView, "alpha", 0.0f, 1.0f);
        a.setDuration(200L);
        a.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void closeStickersView() {
        StickerMasksView stickerMasksView = this.stickersView;
        if (stickerMasksView == null || stickerMasksView.getVisibility() != 0) {
            return;
        }
        this.pickingSticker = false;
        Animator a = ObjectAnimator.ofFloat(this.stickersView, "alpha", 1.0f, 0.0f);
        a.setDuration(200L);
        a.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.8
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                PhotoPaintView.this.stickersView.setVisibility(8);
            }
        });
        a.start();
    }

    private Size baseStickerSize() {
        float side = (float) Math.floor(((double) getPaintingSize().width) * 0.5d);
        return new Size(side, side);
    }

    private void registerRemovalUndo(final EntityView entityView) {
        this.undoStore.registerUndo(entityView.getUUID(), new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$d199QJPchSa3P4DVPHuKrH5EmUU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$registerRemovalUndo$7$PhotoPaintView(entityView);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createSticker(Object parentObject, TLRPC.Document sticker) {
        StickerPosition position = calculateStickerPosition(sticker);
        StickerView view = new StickerView(getContext(), position.position, position.angle, position.scale, baseStickerSize(), sticker, parentObject);
        view.setDelegate(this);
        this.entitiesView.addView(view);
        registerRemovalUndo(view);
        selectEntity(view);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void mirrorSticker() {
        EntityView entityView = this.currentEntityView;
        if (entityView instanceof StickerView) {
            ((StickerView) entityView).mirror();
        }
    }

    private int baseFontSize() {
        return (int) (getPaintingSize().width / 9.0f);
    }

    private void createText() {
        Swatch currentSwatch = this.colorPicker.getSwatch();
        Swatch whiteSwatch = new Swatch(-1, 1.0f, currentSwatch.brushWeight);
        Swatch blackSwatch = new Swatch(-16777216, 0.85f, currentSwatch.brushWeight);
        setCurrentSwatch(this.selectedStroke ? blackSwatch : whiteSwatch, true);
        TextPaintView view = new TextPaintView(getContext(), startPositionRelativeToEntity(null), baseFontSize(), "", this.colorPicker.getSwatch(), this.selectedStroke);
        view.setDelegate(this);
        view.setMaxWidth((int) (getPaintingSize().width - 20.0f));
        this.entitiesView.addView(view, LayoutHelper.createFrame(-2, -2.0f));
        registerRemovalUndo(view);
        selectEntity(view);
        editSelectedTextEntity();
    }

    private void editSelectedTextEntity() {
        if (!(this.currentEntityView instanceof TextPaintView) || this.editingText) {
            return;
        }
        this.curtainView.setVisibility(0);
        TextPaintView textPaintView = (TextPaintView) this.currentEntityView;
        this.initialText = textPaintView.getText();
        this.editingText = true;
        this.editedTextPosition = textPaintView.getPosition();
        this.editedTextRotation = textPaintView.getRotation();
        this.editedTextScale = textPaintView.getScale();
        textPaintView.setPosition(centerPositionForEntity());
        textPaintView.setRotation(0.0f);
        textPaintView.setScale(1.0f);
        this.toolsView.setVisibility(8);
        setTextDimVisibility(true, textPaintView);
        textPaintView.beginEditing();
        InputMethodManager inputMethodManager = (InputMethodManager) ApplicationLoader.applicationContext.getSystemService("input_method");
        inputMethodManager.toggleSoftInputFromWindow(textPaintView.getFocusedView().getWindowToken(), 2, 0);
    }

    public void closeTextEnter(boolean apply) {
        if (this.editingText) {
            EntityView entityView = this.currentEntityView;
            if (!(entityView instanceof TextPaintView)) {
                return;
            }
            TextPaintView textPaintView = (TextPaintView) entityView;
            this.toolsView.setVisibility(0);
            AndroidUtilities.hideKeyboard(textPaintView.getFocusedView());
            textPaintView.getFocusedView().clearFocus();
            textPaintView.endEditing();
            if (!apply) {
                textPaintView.setText(this.initialText);
            }
            if (textPaintView.getText().trim().length() == 0) {
                this.entitiesView.removeView(textPaintView);
                selectEntity(null);
            } else {
                textPaintView.setPosition(this.editedTextPosition);
                textPaintView.setRotation(this.editedTextRotation);
                textPaintView.setScale(this.editedTextScale);
                this.editedTextPosition = null;
                this.editedTextRotation = 0.0f;
                this.editedTextScale = 0.0f;
            }
            setTextDimVisibility(false, textPaintView);
            this.editingText = false;
            this.initialText = null;
            this.curtainView.setVisibility(8);
        }
    }

    private void setBrush(int brush) {
        RenderView renderView = this.renderView;
        Brush[] brushArr = this.brushes;
        this.currentBrush = brush;
        renderView.setBrush(brushArr[brush]);
    }

    private void setStroke(boolean stroke) {
        this.selectedStroke = stroke;
        if (this.currentEntityView instanceof TextPaintView) {
            Swatch currentSwatch = this.colorPicker.getSwatch();
            if (stroke && currentSwatch.color == -1) {
                Swatch blackSwatch = new Swatch(-16777216, 0.85f, currentSwatch.brushWeight);
                setCurrentSwatch(blackSwatch, true);
            } else if (!stroke && currentSwatch.color == -16777216) {
                Swatch blackSwatch2 = new Swatch(-1, 1.0f, currentSwatch.brushWeight);
                setCurrentSwatch(blackSwatch2, true);
            }
            ((TextPaintView) this.currentEntityView).setStroke(stroke);
        }
    }

    private void showMenuForEntity(final EntityView entityView) {
        int x = (int) ((entityView.getPosition().x - (this.entitiesView.getWidth() / 2)) * this.entitiesView.getScaleX());
        int y = ((int) (((entityView.getPosition().y - ((entityView.getHeight() * entityView.getScale()) / 2.0f)) - (this.entitiesView.getHeight() / 2)) * this.entitiesView.getScaleY())) - AndroidUtilities.dp(32.0f);
        showPopup(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$SOudPkur6BhlpOalDb4t5kGoAc0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$showMenuForEntity$11$PhotoPaintView(entityView);
            }
        }, entityView, 17, x, y);
    }

    public /* synthetic */ void lambda$showMenuForEntity$11$PhotoPaintView(final EntityView entityView) {
        LinearLayout parent = new LinearLayout(getContext());
        parent.setOrientation(0);
        TextView deleteView = new TextView(getContext());
        deleteView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem));
        deleteView.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        deleteView.setGravity(16);
        deleteView.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(14.0f), 0);
        deleteView.setTextSize(1, 18.0f);
        deleteView.setTag(0);
        deleteView.setText(LocaleController.getString("PaintDelete", R.string.PaintDelete));
        deleteView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$tTYudnh42zZtp-Ekuao8DDJysXw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$null$8$PhotoPaintView(entityView, view);
            }
        });
        parent.addView(deleteView, LayoutHelper.createLinear(-2, 48));
        if (entityView instanceof TextPaintView) {
            TextView editView = new TextView(getContext());
            editView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem));
            editView.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            editView.setGravity(16);
            editView.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f), 0);
            editView.setTextSize(1, 18.0f);
            editView.setTag(1);
            editView.setText(LocaleController.getString("PaintEdit", R.string.PaintEdit));
            editView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$NLzrC2LTo6R5zOihOtX-6N-G2mc
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$null$9$PhotoPaintView(view);
                }
            });
            parent.addView(editView, LayoutHelper.createLinear(-2, 48));
        }
        TextView duplicateView = new TextView(getContext());
        duplicateView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem));
        duplicateView.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        duplicateView.setGravity(16);
        duplicateView.setPadding(AndroidUtilities.dp(14.0f), 0, AndroidUtilities.dp(16.0f), 0);
        duplicateView.setTextSize(1, 18.0f);
        duplicateView.setTag(2);
        duplicateView.setText(LocaleController.getString("PaintDuplicate", R.string.PaintDuplicate));
        duplicateView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$c1ewVLFuVcujbW6AYgM4lYiRMhM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$null$10$PhotoPaintView(view);
            }
        });
        parent.addView(duplicateView, LayoutHelper.createLinear(-2, 48));
        this.popupLayout.addView(parent);
        LinearLayout.LayoutParams params = (LinearLayout.LayoutParams) parent.getLayoutParams();
        params.width = -2;
        params.height = -2;
        parent.setLayoutParams(params);
    }

    public /* synthetic */ void lambda$null$8$PhotoPaintView(EntityView entityView, View v) {
        lambda$registerRemovalUndo$7$PhotoPaintView(entityView);
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss(true);
        }
    }

    public /* synthetic */ void lambda$null$9$PhotoPaintView(View v) {
        editSelectedTextEntity();
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss(true);
        }
    }

    public /* synthetic */ void lambda$null$10$PhotoPaintView(View v) {
        duplicateSelectedEntity();
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss(true);
        }
    }

    private FrameLayout buttonForBrush(final int brush, int resource, boolean selected) {
        FrameLayout button = new FrameLayout(getContext());
        button.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        button.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$iTWrSUswJkvNQE_4aHsVR6oPK5A
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$buttonForBrush$12$PhotoPaintView(brush, view);
            }
        });
        ImageView preview = new ImageView(getContext());
        preview.setImageResource(resource);
        button.addView(preview, LayoutHelper.createFrame(165.0f, 44.0f, 19, 46.0f, 0.0f, 8.0f, 0.0f));
        if (selected) {
            ImageView check = new ImageView(getContext());
            check.setImageResource(R.drawable.ic_ab_done);
            check.setScaleType(ImageView.ScaleType.CENTER);
            check.setColorFilter(new PorterDuffColorFilter(-13660983, PorterDuff.Mode.MULTIPLY));
            button.addView(check, LayoutHelper.createFrame(50, -1.0f));
        }
        return button;
    }

    public /* synthetic */ void lambda$buttonForBrush$12$PhotoPaintView(int brush, View v) {
        setBrush(brush);
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss(true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showBrushSettings() {
        showPopup(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$lEwfHnFEIPigrQf_fA0OuJ3QB1Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$showBrushSettings$13$PhotoPaintView();
            }
        }, this, 85, 0, AndroidUtilities.dp(48.0f));
    }

    public /* synthetic */ void lambda$showBrushSettings$13$PhotoPaintView() {
        View radial = buttonForBrush(0, R.drawable.paint_radial_preview, this.currentBrush == 0);
        this.popupLayout.addView(radial);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) radial.getLayoutParams();
        layoutParams.width = -1;
        layoutParams.height = AndroidUtilities.dp(52.0f);
        radial.setLayoutParams(layoutParams);
        View elliptical = buttonForBrush(1, R.drawable.paint_elliptical_preview, this.currentBrush == 1);
        this.popupLayout.addView(elliptical);
        LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) elliptical.getLayoutParams();
        layoutParams2.width = -1;
        layoutParams2.height = AndroidUtilities.dp(52.0f);
        elliptical.setLayoutParams(layoutParams2);
        View neon = buttonForBrush(2, R.drawable.paint_neon_preview, this.currentBrush == 2);
        this.popupLayout.addView(neon);
        LinearLayout.LayoutParams layoutParams3 = (LinearLayout.LayoutParams) neon.getLayoutParams();
        layoutParams3.width = -1;
        layoutParams3.height = AndroidUtilities.dp(52.0f);
        neon.setLayoutParams(layoutParams3);
    }

    private FrameLayout buttonForText(final boolean stroke, String text, boolean selected) {
        FrameLayout button = new FrameLayout(getContext()) { // from class: im.uwrkaxlmjj.ui.components.PhotoPaintView.9
            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                return true;
            }
        };
        button.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        button.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$u1JZUA5W-Z8O50VE4COGCxORKJ8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$buttonForText$14$PhotoPaintView(stroke, view);
            }
        });
        EditTextOutline textView = new EditTextOutline(getContext());
        textView.setBackgroundColor(0);
        textView.setEnabled(false);
        textView.setStrokeWidth(AndroidUtilities.dp(3.0f));
        textView.setTextColor(stroke ? -1 : -16777216);
        textView.setStrokeColor(stroke ? -16777216 : 0);
        textView.setPadding(AndroidUtilities.dp(2.0f), 0, AndroidUtilities.dp(2.0f), 0);
        textView.setTextSize(1, 18.0f);
        textView.setTypeface(null, 1);
        textView.setTag(Boolean.valueOf(stroke));
        textView.setText(text);
        button.addView(textView, LayoutHelper.createFrame(-2.0f, -2.0f, 19, 46.0f, 0.0f, 16.0f, 0.0f));
        if (selected) {
            ImageView check = new ImageView(getContext());
            check.setImageResource(R.drawable.ic_ab_done);
            check.setScaleType(ImageView.ScaleType.CENTER);
            check.setColorFilter(new PorterDuffColorFilter(-13660983, PorterDuff.Mode.MULTIPLY));
            button.addView(check, LayoutHelper.createFrame(50, -1.0f));
        }
        return button;
    }

    public /* synthetic */ void lambda$buttonForText$14$PhotoPaintView(boolean stroke, View v) {
        setStroke(stroke);
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss(true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showTextSettings() {
        showPopup(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$kCS49VzdTUIHk5Wv6-k0HsqyDLg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$showTextSettings$15$PhotoPaintView();
            }
        }, this, 85, 0, AndroidUtilities.dp(48.0f));
    }

    public /* synthetic */ void lambda$showTextSettings$15$PhotoPaintView() {
        View outline = buttonForText(true, LocaleController.getString("PaintOutlined", R.string.PaintOutlined), this.selectedStroke);
        this.popupLayout.addView(outline);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) outline.getLayoutParams();
        layoutParams.width = -1;
        layoutParams.height = AndroidUtilities.dp(48.0f);
        outline.setLayoutParams(layoutParams);
        View regular = buttonForText(false, LocaleController.getString("PaintRegular", R.string.PaintRegular), true ^ this.selectedStroke);
        this.popupLayout.addView(regular);
        LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) regular.getLayoutParams();
        layoutParams2.width = -1;
        layoutParams2.height = AndroidUtilities.dp(48.0f);
        regular.setLayoutParams(layoutParams2);
    }

    private void showPopup(Runnable setupRunnable, View parent, int gravity, int x, int y) {
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss();
            return;
        }
        if (this.popupLayout == null) {
            this.popupRect = new android.graphics.Rect();
            ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = new ActionBarPopupWindow.ActionBarPopupWindowLayout(getContext());
            this.popupLayout = actionBarPopupWindowLayout;
            actionBarPopupWindowLayout.setAnimationEnabled(false);
            this.popupLayout.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$F7xehqe8TzPsbbbuIj0UIFaDKNA
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view, MotionEvent motionEvent) {
                    return this.f$0.lambda$showPopup$16$PhotoPaintView(view, motionEvent);
                }
            });
            this.popupLayout.setDispatchKeyEventListener(new ActionBarPopupWindow.OnDispatchKeyEventListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$Aho6gZi-A56vSNDgZW3CV9W8I8c
                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow.OnDispatchKeyEventListener
                public final void onDispatchKeyEvent(KeyEvent keyEvent) {
                    this.f$0.lambda$showPopup$17$PhotoPaintView(keyEvent);
                }
            });
            this.popupLayout.setShowedFromBotton(true);
        }
        this.popupLayout.removeInnerViews();
        setupRunnable.run();
        if (this.popupWindow == null) {
            ActionBarPopupWindow actionBarPopupWindow2 = new ActionBarPopupWindow(this.popupLayout, -2, -2);
            this.popupWindow = actionBarPopupWindow2;
            actionBarPopupWindow2.setAnimationEnabled(false);
            this.popupWindow.setAnimationStyle(R.plurals.PopupAnimation);
            this.popupWindow.setOutsideTouchable(true);
            this.popupWindow.setClippingEnabled(true);
            this.popupWindow.setInputMethodMode(2);
            this.popupWindow.setSoftInputMode(0);
            this.popupWindow.getContentView().setFocusableInTouchMode(true);
            this.popupWindow.setOnDismissListener(new PopupWindow.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$9R0KD8kmSdLAqEwLuydPFyeeGE0
                @Override // android.widget.PopupWindow.OnDismissListener
                public final void onDismiss() {
                    this.f$0.lambda$showPopup$18$PhotoPaintView();
                }
            });
        }
        this.popupLayout.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(1000.0f), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(1000.0f), Integer.MIN_VALUE));
        this.popupWindow.setFocusable(true);
        this.popupWindow.showAtLocation(parent, gravity, x, y);
        this.popupWindow.startAnimation();
    }

    public /* synthetic */ boolean lambda$showPopup$16$PhotoPaintView(View v, MotionEvent event) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (event.getActionMasked() == 0 && (actionBarPopupWindow = this.popupWindow) != null && actionBarPopupWindow.isShowing()) {
            v.getHitRect(this.popupRect);
            if (!this.popupRect.contains((int) event.getX(), (int) event.getY())) {
                this.popupWindow.dismiss();
                return false;
            }
            return false;
        }
        return false;
    }

    public /* synthetic */ void lambda$showPopup$17$PhotoPaintView(KeyEvent keyEvent) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (keyEvent.getKeyCode() == 4 && keyEvent.getRepeatCount() == 0 && (actionBarPopupWindow = this.popupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss();
        }
    }

    public /* synthetic */ void lambda$showPopup$18$PhotoPaintView() {
        this.popupLayout.removeInnerViews();
    }

    private int getFrameRotation() {
        int i = this.orientation;
        if (i == 90) {
            return 1;
        }
        if (i == 180) {
            return 2;
        }
        if (i == 270) {
            return 3;
        }
        return 0;
    }

    private void detectFaces() {
        this.queue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoPaintView$N7K-JqE1en8ApHsMDKAFPqXSzho
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$detectFaces$19$PhotoPaintView();
            }
        });
    }

    public /* synthetic */ void lambda$detectFaces$19$PhotoPaintView() {
        FaceDetector faceDetector = null;
        try {
            try {
                faceDetector = new FaceDetector.Builder(getContext()).setMode(1).setLandmarkType(1).setTrackingEnabled(false).build();
            } catch (Throwable th) {
                if (0 != 0) {
                    faceDetector.release();
                }
                throw th;
            }
        } catch (Exception e) {
            FileLog.e(e);
            if (0 == 0) {
                return;
            }
        }
        if (!faceDetector.isOperational()) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("face detection is not operational");
            }
            if (faceDetector != null) {
                faceDetector.release();
                return;
            }
            return;
        }
        Frame frame = new Frame.Builder().setBitmap(this.bitmapToEdit).setRotation(getFrameRotation()).build();
        try {
            SparseArray<Face> faces = faceDetector.detect(frame);
            ArrayList<PhotoFace> result = new ArrayList<>();
            Size targetSize = getPaintingSize();
            for (int i = 0; i < faces.size(); i++) {
                int key = faces.keyAt(i);
                Face f = faces.get(key);
                PhotoFace face = new PhotoFace(f, this.bitmapToEdit, targetSize, isSidewardOrientation());
                if (face.isSufficient()) {
                    result.add(face);
                }
            }
            this.faces = result;
            if (faceDetector == null) {
                return;
            }
            faceDetector.release();
        } catch (Throwable e2) {
            FileLog.e(e2);
            if (faceDetector != null) {
                faceDetector.release();
            }
        }
    }

    private StickerPosition calculateStickerPosition(TLRPC.Document document) {
        ArrayList<PhotoFace> arrayList;
        int anchor;
        PhotoFace face;
        TLRPC.TL_maskCoords maskCoords = null;
        int a = 0;
        while (true) {
            if (a >= document.attributes.size()) {
                break;
            }
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (!(attribute instanceof TLRPC.TL_documentAttributeSticker)) {
                a++;
            } else {
                maskCoords = attribute.mask_coords;
                break;
            }
        }
        StickerPosition defaultPosition = new StickerPosition(centerPositionForEntity(), 0.75f, 0.0f);
        if (maskCoords == null || (arrayList = this.faces) == null || arrayList.size() == 0 || (face = getRandomFaceWithVacantAnchor((anchor = maskCoords.n), document.id, maskCoords)) == null) {
            return defaultPosition;
        }
        Point referencePoint = face.getPointForAnchor(anchor);
        float referenceWidth = face.getWidthForAnchor(anchor);
        float angle = face.getAngle();
        Size baseSize = baseStickerSize();
        float scale = (float) (((double) (referenceWidth / baseSize.width)) * maskCoords.zoom);
        float radAngle = (float) Math.toRadians(angle);
        float xCompX = (float) (Math.sin(1.5707963267948966d - ((double) radAngle)) * ((double) referenceWidth) * maskCoords.x);
        float xCompY = (float) (Math.cos(1.5707963267948966d - ((double) radAngle)) * ((double) referenceWidth) * maskCoords.x);
        float yCompX = (float) (Math.cos(((double) radAngle) + 1.5707963267948966d) * ((double) referenceWidth) * maskCoords.y);
        float yCompY = (float) (Math.sin(((double) radAngle) + 1.5707963267948966d) * ((double) referenceWidth) * maskCoords.y);
        float x = referencePoint.x + xCompX + yCompX;
        float y = referencePoint.y + xCompY + yCompY;
        return new StickerPosition(new Point(x, y), scale, angle);
    }

    private PhotoFace getRandomFaceWithVacantAnchor(int anchor, long documentId, TLRPC.TL_maskCoords maskCoords) {
        if (anchor < 0 || anchor > 3 || this.faces.isEmpty()) {
            return null;
        }
        int count = this.faces.size();
        int randomIndex = Utilities.random.nextInt(count);
        int i = randomIndex;
        for (int remaining = count; remaining > 0; remaining--) {
            PhotoFace face = this.faces.get(i);
            if (isFaceAnchorOccupied(face, anchor, documentId, maskCoords)) {
                i = (i + 1) % count;
            } else {
                return face;
            }
        }
        return null;
    }

    private boolean isFaceAnchorOccupied(PhotoFace face, int anchor, long documentId, TLRPC.TL_maskCoords maskCoords) {
        Point anchorPoint = face.getPointForAnchor(anchor);
        if (anchorPoint == null) {
            return true;
        }
        float minDistance = face.getWidthForAnchor(0) * 1.1f;
        for (int index = 0; index < this.entitiesView.getChildCount(); index++) {
            View view = this.entitiesView.getChildAt(index);
            if (view instanceof StickerView) {
                StickerView stickerView = (StickerView) view;
                if (stickerView.getAnchor() != anchor) {
                    continue;
                } else {
                    Point location = stickerView.getPosition();
                    float distance = (float) Math.hypot(location.x - anchorPoint.x, location.y - anchorPoint.y);
                    if ((documentId == stickerView.getSticker().id || this.faces.size() > 1) && distance < minDistance) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private class StickerPosition {
        private float angle;
        private Point position;
        private float scale;

        StickerPosition(Point position, float scale, float angle) {
            this.position = position;
            this.scale = scale;
            this.angle = angle;
        }
    }
}
