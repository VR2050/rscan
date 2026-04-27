package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.RectF;
import android.os.Build;
import android.text.Selection;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.util.Property;
import android.util.SparseArray;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.FileRefController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ContentPreviewViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.cells.FeaturedStickerSetInfoCell;
import im.uwrkaxlmjj.ui.cells.StickerEmojiCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class StickersAlert extends BottomSheet implements NotificationCenter.NotificationCenterDelegate {
    private GridAdapter adapter;
    private boolean clearsInputField;
    private StickersAlertDelegate delegate;
    private FrameLayout emptyView;
    private RecyclerListView gridView;
    private boolean ignoreLayout;
    private TLRPC.InputStickerSet inputStickerSet;
    private StickersAlertInstallDelegate installDelegate;
    private int itemSize;
    private GridLayoutManager layoutManager;
    private ActionBarMenuItem optionsButton;
    private Activity parentActivity;
    private BaseFragment parentFragment;
    private TextView pickerBottomLayout;
    private ContentPreviewViewer.ContentPreviewViewerDelegate previewDelegate;
    private TextView previewSendButton;
    private View previewSendButtonShadow;
    private int reqId;
    private int scrollOffsetY;
    private TLRPC.Document selectedSticker;
    private View[] shadow;
    private AnimatorSet[] shadowAnimation;
    private boolean showEmoji;
    private TextView stickerEmojiTextView;
    private BackupImageView stickerImageView;
    private FrameLayout stickerPreviewLayout;
    private TLRPC.TL_messages_stickerSet stickerSet;
    private ArrayList<TLRPC.StickerSetCovered> stickerSetCovereds;
    private RecyclerListView.OnItemClickListener stickersOnItemClickListener;
    private TextView titleTextView;
    private Pattern urlPattern;

    public interface StickersAlertDelegate {
        boolean canSchedule();

        boolean isInScheduleMode();

        /* JADX INFO: renamed from: onStickerSelected */
        void lambda$onStickerSelected$28$ChatActivityEnterView(TLRPC.Document document, Object obj, boolean z, boolean z2, int i);
    }

    public interface StickersAlertInstallDelegate {
        void onStickerSetInstalled();

        void onStickerSetUninstalled();
    }

    private static class LinkMovementMethodMy extends LinkMovementMethod {
        private LinkMovementMethodMy() {
        }

        @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
        public boolean onTouchEvent(TextView widget, Spannable buffer, MotionEvent event) {
            try {
                boolean result = super.onTouchEvent(widget, buffer, event);
                if (event.getAction() == 1 || event.getAction() == 3) {
                    Selection.removeSelection(buffer);
                }
                return result;
            } catch (Exception e) {
                FileLog.e(e);
                return false;
            }
        }
    }

    public StickersAlert(Context context, final Object parentObject, TLRPC.Photo photo) {
        super(context, false, 1);
        this.shadowAnimation = new AnimatorSet[2];
        this.shadow = new View[2];
        this.previewDelegate = new ContentPreviewViewer.ContentPreviewViewerDelegate() { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.1
            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public /* synthetic */ void gifAddedOrDeleted() {
                ContentPreviewViewer.ContentPreviewViewerDelegate.CC.$default$gifAddedOrDeleted(this);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public /* synthetic */ void sendGif(Object obj, boolean z, int i) {
                ContentPreviewViewer.ContentPreviewViewerDelegate.CC.$default$sendGif(this, obj, z, i);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void sendSticker(TLRPC.Document sticker, Object parent, boolean notify, int scheduleDate) {
                if (StickersAlert.this.delegate != null) {
                    StickersAlert.this.delegate.lambda$onStickerSelected$28$ChatActivityEnterView(sticker, parent, StickersAlert.this.clearsInputField, notify, scheduleDate);
                    StickersAlert.this.dismiss();
                }
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean canSchedule() {
                return StickersAlert.this.delegate != null && StickersAlert.this.delegate.canSchedule();
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean isInScheduleMode() {
                return StickersAlert.this.delegate != null && StickersAlert.this.delegate.isInScheduleMode();
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void openSet(TLRPC.InputStickerSet set, boolean clearsInputField) {
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean needSend() {
                return StickersAlert.this.previewSendButton.getVisibility() == 0;
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean needOpen() {
                return false;
            }
        };
        this.parentActivity = (Activity) context;
        final TLRPC.TL_messages_getAttachedStickers req = new TLRPC.TL_messages_getAttachedStickers();
        TLRPC.TL_inputStickeredMediaPhoto inputStickeredMediaPhoto = new TLRPC.TL_inputStickeredMediaPhoto();
        inputStickeredMediaPhoto.id = new TLRPC.TL_inputPhoto();
        inputStickeredMediaPhoto.id.id = photo.id;
        inputStickeredMediaPhoto.id.access_hash = photo.access_hash;
        inputStickeredMediaPhoto.id.file_reference = photo.file_reference;
        if (inputStickeredMediaPhoto.id.file_reference == null) {
            inputStickeredMediaPhoto.id.file_reference = new byte[0];
        }
        req.media = inputStickeredMediaPhoto;
        final RequestDelegate requestDelegate = new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$ir-dAz6hV5gV6tEdpdnXxBaKr7E
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$new$1$StickersAlert(req, tLObject, tL_error);
            }
        };
        this.reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$4AwhedL3z6I0ofU3sQTTyXubbQ4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$new$2$StickersAlert(parentObject, req, requestDelegate, tLObject, tL_error);
            }
        });
        init(context);
    }

    public /* synthetic */ void lambda$new$1$StickersAlert(final TLRPC.TL_messages_getAttachedStickers req, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$s-BLFc4lYDOzUFOQbv1ZaVKziPE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$StickersAlert(error, response, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$StickersAlert(TLRPC.TL_error error, TLObject response, TLRPC.TL_messages_getAttachedStickers req) {
        this.reqId = 0;
        if (error != null) {
            AlertsCreator.processError(this.currentAccount, error, this.parentFragment, req, new Object[0]);
            dismiss();
            return;
        }
        TLRPC.Vector vector = (TLRPC.Vector) response;
        if (vector.objects.isEmpty()) {
            dismiss();
            return;
        }
        if (vector.objects.size() == 1) {
            TLRPC.StickerSetCovered set = (TLRPC.StickerSetCovered) vector.objects.get(0);
            TLRPC.TL_inputStickerSetID tL_inputStickerSetID = new TLRPC.TL_inputStickerSetID();
            this.inputStickerSet = tL_inputStickerSetID;
            tL_inputStickerSetID.id = set.set.id;
            this.inputStickerSet.access_hash = set.set.access_hash;
            loadStickerSet();
            return;
        }
        this.stickerSetCovereds = new ArrayList<>();
        for (int a = 0; a < vector.objects.size(); a++) {
            this.stickerSetCovereds.add((TLRPC.StickerSetCovered) vector.objects.get(a));
        }
        this.gridView.setLayoutParams(LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, 48.0f));
        this.titleTextView.setVisibility(8);
        this.shadow[0].setVisibility(8);
        this.adapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$new$2$StickersAlert(Object parentObject, TLRPC.TL_messages_getAttachedStickers req, RequestDelegate requestDelegate, TLObject response, TLRPC.TL_error error) {
        if (error != null && FileRefController.isFileRefError(error.text) && parentObject != null) {
            FileRefController.getInstance(this.currentAccount).requestReference(parentObject, req, requestDelegate);
        } else {
            requestDelegate.run(response, error);
        }
    }

    public StickersAlert(Context context, BaseFragment baseFragment, TLRPC.InputStickerSet set, TLRPC.TL_messages_stickerSet loadedSet, StickersAlertDelegate stickersAlertDelegate) {
        super(context, false, 1);
        this.shadowAnimation = new AnimatorSet[2];
        this.shadow = new View[2];
        this.previewDelegate = new ContentPreviewViewer.ContentPreviewViewerDelegate() { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.1
            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public /* synthetic */ void gifAddedOrDeleted() {
                ContentPreviewViewer.ContentPreviewViewerDelegate.CC.$default$gifAddedOrDeleted(this);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public /* synthetic */ void sendGif(Object obj, boolean z, int i) {
                ContentPreviewViewer.ContentPreviewViewerDelegate.CC.$default$sendGif(this, obj, z, i);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void sendSticker(TLRPC.Document sticker, Object parent, boolean notify, int scheduleDate) {
                if (StickersAlert.this.delegate != null) {
                    StickersAlert.this.delegate.lambda$onStickerSelected$28$ChatActivityEnterView(sticker, parent, StickersAlert.this.clearsInputField, notify, scheduleDate);
                    StickersAlert.this.dismiss();
                }
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean canSchedule() {
                return StickersAlert.this.delegate != null && StickersAlert.this.delegate.canSchedule();
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean isInScheduleMode() {
                return StickersAlert.this.delegate != null && StickersAlert.this.delegate.isInScheduleMode();
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void openSet(TLRPC.InputStickerSet set2, boolean clearsInputField) {
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean needSend() {
                return StickersAlert.this.previewSendButton.getVisibility() == 0;
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean needOpen() {
                return false;
            }
        };
        this.delegate = stickersAlertDelegate;
        this.inputStickerSet = set;
        this.stickerSet = loadedSet;
        this.parentFragment = baseFragment;
        loadStickerSet();
        init(context);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog
    public void show() {
        super.show();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 2);
    }

    public void setClearsInputField(boolean value) {
        this.clearsInputField = value;
    }

    public boolean isClearsInputField() {
        return this.clearsInputField;
    }

    private void loadStickerSet() {
        TLRPC.InputStickerSet inputStickerSet = this.inputStickerSet;
        if (inputStickerSet != null) {
            if (this.stickerSet == null && inputStickerSet.short_name != null) {
                this.stickerSet = MediaDataController.getInstance(this.currentAccount).getStickerSetByName(this.inputStickerSet.short_name);
            }
            if (this.stickerSet == null) {
                this.stickerSet = MediaDataController.getInstance(this.currentAccount).getStickerSetById(this.inputStickerSet.id);
            }
            if (this.stickerSet == null) {
                TLRPC.TL_messages_getStickerSet req = new TLRPC.TL_messages_getStickerSet();
                req.stickerset = this.inputStickerSet;
                ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$F_lp00TXYb9neX3kndqtrspd1mU
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$loadStickerSet$4$StickersAlert(tLObject, tL_error);
                    }
                });
            } else if (this.adapter != null) {
                updateSendButton();
                updateFields();
                this.adapter.notifyDataSetChanged();
            }
        }
        if (this.stickerSet != null) {
            this.showEmoji = !r0.set.masks;
        }
    }

    public /* synthetic */ void lambda$loadStickerSet$4$StickersAlert(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$ImL6ac0z0y__JdpioTYrgnOli1g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$StickersAlert(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$StickersAlert(TLRPC.TL_error error, TLObject response) {
        this.reqId = 0;
        if (error == null) {
            this.optionsButton.setVisibility(0);
            this.stickerSet = (TLRPC.TL_messages_stickerSet) response;
            this.showEmoji = !r0.set.masks;
            updateSendButton();
            updateFields();
            this.adapter.notifyDataSetChanged();
            return;
        }
        ToastUtils.show(R.string.AddStickersNotFound);
        dismiss();
    }

    private void init(Context context) {
        this.containerView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.2
            private boolean fullHeight;
            private int lastNotifyWidth;
            private RectF rect = new RectF();

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (ev.getAction() == 0 && StickersAlert.this.scrollOffsetY != 0 && ev.getY() < StickersAlert.this.scrollOffsetY) {
                    StickersAlert.this.dismiss();
                    return true;
                }
                return super.onInterceptTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                return !StickersAlert.this.isDismissed() && super.onTouchEvent(e);
            }

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int contentSize;
                int height = View.MeasureSpec.getSize(heightMeasureSpec);
                if (Build.VERSION.SDK_INT >= 21) {
                    StickersAlert.this.ignoreLayout = true;
                    setPadding(StickersAlert.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight, StickersAlert.this.backgroundPaddingLeft, 0);
                    StickersAlert.this.ignoreLayout = false;
                }
                StickersAlert.this.itemSize = (View.MeasureSpec.getSize(widthMeasureSpec) - AndroidUtilities.dp(36.0f)) / 5;
                if (StickersAlert.this.stickerSetCovereds != null) {
                    contentSize = AndroidUtilities.dp(56.0f) + (AndroidUtilities.dp(60.0f) * StickersAlert.this.stickerSetCovereds.size()) + (StickersAlert.this.adapter.stickersRowCount * AndroidUtilities.dp(82.0f)) + StickersAlert.this.backgroundPaddingTop + AndroidUtilities.dp(24.0f);
                } else {
                    contentSize = AndroidUtilities.dp(96.0f) + (Math.max(3, StickersAlert.this.stickerSet != null ? (int) Math.ceil(StickersAlert.this.stickerSet.documents.size() / 5.0f) : 0) * AndroidUtilities.dp(82.0f)) + StickersAlert.this.backgroundPaddingTop + AndroidUtilities.statusBarHeight;
                }
                int padding = ((double) contentSize) < ((double) (height / 5)) * 3.2d ? 0 : (height / 5) * 2;
                if (padding != 0 && contentSize < height) {
                    padding -= height - contentSize;
                }
                if (padding == 0) {
                    padding = StickersAlert.this.backgroundPaddingTop;
                }
                if (StickersAlert.this.stickerSetCovereds != null) {
                    padding += AndroidUtilities.dp(8.0f);
                }
                if (StickersAlert.this.gridView.getPaddingTop() != padding) {
                    StickersAlert.this.ignoreLayout = true;
                    StickersAlert.this.gridView.setPadding(AndroidUtilities.dp(10.0f), padding, AndroidUtilities.dp(10.0f), 0);
                    StickersAlert.this.emptyView.setPadding(0, padding, 0, 0);
                    StickersAlert.this.ignoreLayout = false;
                }
                this.fullHeight = contentSize >= height;
                super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(Math.min(contentSize, height), 1073741824));
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                if (this.lastNotifyWidth != right - left) {
                    this.lastNotifyWidth = right - left;
                    if (StickersAlert.this.adapter != null && StickersAlert.this.stickerSetCovereds != null) {
                        StickersAlert.this.adapter.notifyDataSetChanged();
                    }
                }
                super.onLayout(changed, left, top, right, bottom);
                StickersAlert.this.updateLayout();
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (StickersAlert.this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                int y;
                int top;
                int height;
                int statusBarHeight;
                float radProgress;
                int y2 = (StickersAlert.this.scrollOffsetY - StickersAlert.this.backgroundPaddingTop) + AndroidUtilities.dp(6.0f);
                int top2 = (StickersAlert.this.scrollOffsetY - StickersAlert.this.backgroundPaddingTop) - AndroidUtilities.dp(13.0f);
                int height2 = getMeasuredHeight() + AndroidUtilities.dp(15.0f) + StickersAlert.this.backgroundPaddingTop;
                float radProgress2 = 1.0f;
                if (Build.VERSION.SDK_INT < 21) {
                    y = y2;
                    top = top2;
                    height = height2;
                    statusBarHeight = 0;
                    radProgress = 1.0f;
                } else {
                    int top3 = top2 + AndroidUtilities.statusBarHeight;
                    int y3 = y2 + AndroidUtilities.statusBarHeight;
                    int height3 = height2 - AndroidUtilities.statusBarHeight;
                    if (this.fullHeight) {
                        if (StickersAlert.this.backgroundPaddingTop + top3 < AndroidUtilities.statusBarHeight * 2) {
                            int diff = Math.min(AndroidUtilities.statusBarHeight, ((AndroidUtilities.statusBarHeight * 2) - top3) - StickersAlert.this.backgroundPaddingTop);
                            top3 -= diff;
                            height3 += diff;
                            radProgress2 = 1.0f - Math.min(1.0f, (diff * 2) / AndroidUtilities.statusBarHeight);
                        }
                        if (StickersAlert.this.backgroundPaddingTop + top3 < AndroidUtilities.statusBarHeight) {
                            int statusBarHeight2 = Math.min(AndroidUtilities.statusBarHeight, (AndroidUtilities.statusBarHeight - top3) - StickersAlert.this.backgroundPaddingTop);
                            y = y3;
                            top = top3;
                            height = height3;
                            statusBarHeight = statusBarHeight2;
                            radProgress = radProgress2;
                        } else {
                            y = y3;
                            top = top3;
                            height = height3;
                            statusBarHeight = 0;
                            radProgress = radProgress2;
                        }
                    } else {
                        y = y3;
                        top = top3;
                        height = height3;
                        statusBarHeight = 0;
                        radProgress = 1.0f;
                    }
                }
                StickersAlert.this.shadowDrawable.setBounds(0, top, getMeasuredWidth(), height);
                StickersAlert.this.shadowDrawable.draw(canvas);
                if (radProgress != 1.0f) {
                    Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_dialogBackground));
                    this.rect.set(StickersAlert.this.backgroundPaddingLeft, StickersAlert.this.backgroundPaddingTop + top, getMeasuredWidth() - StickersAlert.this.backgroundPaddingLeft, StickersAlert.this.backgroundPaddingTop + top + AndroidUtilities.dp(24.0f));
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(12.0f) * radProgress, AndroidUtilities.dp(12.0f) * radProgress, Theme.dialogs_onlineCirclePaint);
                }
                int w = AndroidUtilities.dp(36.0f);
                this.rect.set((getMeasuredWidth() - w) / 2, y, (getMeasuredWidth() + w) / 2, AndroidUtilities.dp(4.0f) + y);
                Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_sheet_scrollUp));
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), Theme.dialogs_onlineCirclePaint);
                if (statusBarHeight > 0) {
                    int color1 = Theme.getColor(Theme.key_dialogBackground);
                    int finalColor = Color.argb(255, (int) (Color.red(color1) * 0.8f), (int) (Color.green(color1) * 0.8f), (int) (Color.blue(color1) * 0.8f));
                    Theme.dialogs_onlineCirclePaint.setColor(finalColor);
                    canvas.drawRect(StickersAlert.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight - statusBarHeight, getMeasuredWidth() - StickersAlert.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight, Theme.dialogs_onlineCirclePaint);
                }
            }
        };
        this.containerView.setWillNotDraw(false);
        this.containerView.setPadding(this.backgroundPaddingLeft, 0, this.backgroundPaddingLeft, 0);
        FrameLayout.LayoutParams frameLayoutParams = new FrameLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight(), 51);
        frameLayoutParams.topMargin = AndroidUtilities.dp(48.0f);
        this.shadow[0] = new View(context);
        this.shadow[0].setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.shadow[0].setAlpha(0.0f);
        this.shadow[0].setVisibility(4);
        this.shadow[0].setTag(1);
        this.containerView.addView(this.shadow[0], frameLayoutParams);
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.3
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent event) {
                boolean result = ContentPreviewViewer.getInstance().onInterceptTouchEvent(event, StickersAlert.this.gridView, 0, StickersAlert.this.previewDelegate);
                return super.onInterceptTouchEvent(event) || result;
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (StickersAlert.this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        this.gridView = recyclerListView;
        recyclerListView.setTag(14);
        RecyclerListView recyclerListView2 = this.gridView;
        GridLayoutManager gridLayoutManager = new GridLayoutManager(getContext(), 5);
        this.layoutManager = gridLayoutManager;
        recyclerListView2.setLayoutManager(gridLayoutManager);
        this.layoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.4
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                if ((StickersAlert.this.stickerSetCovereds == null || !(StickersAlert.this.adapter.cache.get(position) instanceof Integer)) && position != StickersAlert.this.adapter.totalItems) {
                    return 1;
                }
                return StickersAlert.this.adapter.stickersPerRow;
            }
        });
        RecyclerListView recyclerListView3 = this.gridView;
        GridAdapter gridAdapter = new GridAdapter(context);
        this.adapter = gridAdapter;
        recyclerListView3.setAdapter(gridAdapter);
        this.gridView.setVerticalScrollBarEnabled(false);
        this.gridView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.5
            @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
            public void getItemOffsets(android.graphics.Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
                outRect.left = 0;
                outRect.right = 0;
                outRect.bottom = 0;
                outRect.top = 0;
            }
        });
        this.gridView.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
        this.gridView.setClipToPadding(false);
        this.gridView.setEnabled(true);
        this.gridView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.gridView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$fvti5IaGXThkemF3iEnpaC8lRD8
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return this.f$0.lambda$init$5$StickersAlert(view, motionEvent);
            }
        });
        this.gridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.6
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                StickersAlert.this.updateLayout();
            }
        });
        RecyclerListView.OnItemClickListener onItemClickListener = new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$80i1aYpVUwo6tYBluSK2cv0jOIQ
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$init$6$StickersAlert(view, i);
            }
        };
        this.stickersOnItemClickListener = onItemClickListener;
        this.gridView.setOnItemClickListener(onItemClickListener);
        this.containerView.addView(this.gridView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 48.0f, 0.0f, 48.0f));
        this.emptyView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.7
            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (StickersAlert.this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        this.containerView.addView(this.emptyView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, 48.0f));
        this.gridView.setEmptyView(this.emptyView);
        this.emptyView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$QXpbYocywE0q6LTHzBbGeLlySwk
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return StickersAlert.lambda$init$7(view, motionEvent);
            }
        });
        TextView textView = new TextView(context);
        this.titleTextView = textView;
        textView.setLines(1);
        this.titleTextView.setSingleLine(true);
        this.titleTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.titleTextView.setTextSize(1, 20.0f);
        this.titleTextView.setLinkTextColor(Theme.getColor(Theme.key_dialogTextLink));
        this.titleTextView.setHighlightColor(Theme.getColor(Theme.key_dialogLinkSelection));
        this.titleTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.titleTextView.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        this.titleTextView.setGravity(16);
        this.titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.containerView.addView(this.titleTextView, LayoutHelper.createFrame(-1.0f, 50.0f, 51, 0.0f, 0.0f, 40.0f, 0.0f));
        ActionBarMenuItem actionBarMenuItem = new ActionBarMenuItem(context, null, 0, Theme.getColor(Theme.key_sheet_other));
        this.optionsButton = actionBarMenuItem;
        actionBarMenuItem.setLongClickEnabled(false);
        this.optionsButton.setSubMenuOpenSide(2);
        this.optionsButton.setIcon(R.drawable.ic_ab_other);
        this.optionsButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_player_actionBarSelector), 1));
        this.containerView.addView(this.optionsButton, LayoutHelper.createFrame(40.0f, 40.0f, 53, 0.0f, 5.0f, 5.0f, 0.0f));
        this.optionsButton.addSubItem(1, R.drawable.msg_share, LocaleController.getString("StickersShare", R.string.StickersShare));
        this.optionsButton.addSubItem(2, R.drawable.msg_link, LocaleController.getString("CopyLink", R.string.CopyLink));
        this.optionsButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$UYa0XG7u0aIZKybXYQ2fM7zF4M8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$init$8$StickersAlert(view);
            }
        });
        this.optionsButton.setDelegate(new ActionBarMenuItem.ActionBarMenuItemDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$-6rEGdA_rYooyN1pWId5s4MZSTM
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemDelegate
            public final void onItemClick(int i) {
                this.f$0.onSubItemClick(i);
            }
        });
        this.optionsButton.setContentDescription(LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
        this.optionsButton.setVisibility(this.inputStickerSet != null ? 0 : 8);
        RadialProgressView progressView = new RadialProgressView(context);
        this.emptyView.addView(progressView, LayoutHelper.createFrame(-2, -2, 17));
        FrameLayout.LayoutParams frameLayoutParams2 = new FrameLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight(), 83);
        frameLayoutParams2.bottomMargin = AndroidUtilities.dp(48.0f);
        this.shadow[1] = new View(context);
        this.shadow[1].setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.containerView.addView(this.shadow[1], frameLayoutParams2);
        TextView textView2 = new TextView(context);
        this.pickerBottomLayout = textView2;
        textView2.setBackgroundDrawable(Theme.createSelectorWithBackgroundDrawable(Theme.getColor(Theme.key_dialogBackground), Theme.getColor(Theme.key_listSelector)));
        this.pickerBottomLayout.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        this.pickerBottomLayout.setTextSize(1, 14.0f);
        this.pickerBottomLayout.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        this.pickerBottomLayout.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.pickerBottomLayout.setGravity(17);
        this.containerView.addView(this.pickerBottomLayout, LayoutHelper.createFrame(-1, 48, 83));
        FrameLayout frameLayout = new FrameLayout(context);
        this.stickerPreviewLayout = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground) & (-536870913));
        this.stickerPreviewLayout.setVisibility(8);
        this.stickerPreviewLayout.setSoundEffectsEnabled(false);
        this.containerView.addView(this.stickerPreviewLayout, LayoutHelper.createFrame(-1, -1.0f));
        this.stickerPreviewLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$9Ti0tLSLOtADB3LloVogc_yIhmc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$init$9$StickersAlert(view);
            }
        });
        BackupImageView backupImageView = new BackupImageView(context);
        this.stickerImageView = backupImageView;
        backupImageView.setAspectFit(true);
        this.stickerImageView.setLayerNum(3);
        this.stickerPreviewLayout.addView(this.stickerImageView);
        TextView textView3 = new TextView(context);
        this.stickerEmojiTextView = textView3;
        textView3.setTextSize(1, 30.0f);
        this.stickerEmojiTextView.setGravity(85);
        this.stickerPreviewLayout.addView(this.stickerEmojiTextView);
        TextView textView4 = new TextView(context);
        this.previewSendButton = textView4;
        textView4.setTextSize(1, 14.0f);
        this.previewSendButton.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        this.previewSendButton.setGravity(17);
        this.previewSendButton.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.previewSendButton.setPadding(AndroidUtilities.dp(29.0f), 0, AndroidUtilities.dp(29.0f), 0);
        this.previewSendButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.stickerPreviewLayout.addView(this.previewSendButton, LayoutHelper.createFrame(-1, 48, 83));
        this.previewSendButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$HpF45jyfQ6soh0FyKcW5MpzH9DA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$init$10$StickersAlert(view);
            }
        });
        FrameLayout.LayoutParams frameLayoutParams3 = new FrameLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight(), 83);
        frameLayoutParams3.bottomMargin = AndroidUtilities.dp(48.0f);
        View view = new View(context);
        this.previewSendButtonShadow = view;
        view.setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.stickerPreviewLayout.addView(this.previewSendButtonShadow, frameLayoutParams3);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        updateFields();
        updateSendButton();
        this.adapter.notifyDataSetChanged();
    }

    public /* synthetic */ boolean lambda$init$5$StickersAlert(View v, MotionEvent event) {
        return ContentPreviewViewer.getInstance().onTouch(event, this.gridView, 0, this.stickersOnItemClickListener, this.previewDelegate);
    }

    public /* synthetic */ void lambda$init$6$StickersAlert(View view, int position) {
        if (this.stickerSetCovereds == null) {
            TLRPC.TL_messages_stickerSet tL_messages_stickerSet = this.stickerSet;
            if (tL_messages_stickerSet == null || position < 0 || position >= tL_messages_stickerSet.documents.size()) {
                return;
            }
            this.selectedSticker = this.stickerSet.documents.get(position);
            boolean set = false;
            int a = 0;
            while (true) {
                if (a >= this.selectedSticker.attributes.size()) {
                    break;
                }
                TLRPC.DocumentAttribute attribute = this.selectedSticker.attributes.get(a);
                if (!(attribute instanceof TLRPC.TL_documentAttributeSticker)) {
                    a++;
                } else if (attribute.alt != null && attribute.alt.length() > 0) {
                    this.stickerEmojiTextView.setText(Emoji.replaceEmoji(attribute.alt, this.stickerEmojiTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(30.0f), false));
                    set = true;
                }
            }
            if (!set) {
                this.stickerEmojiTextView.setText(Emoji.replaceEmoji(MediaDataController.getInstance(this.currentAccount).getEmojiForSticker(this.selectedSticker.id), this.stickerEmojiTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(30.0f), false));
            }
            TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(this.selectedSticker.thumbs, 90);
            this.stickerImageView.getImageReceiver().setImage(ImageLocation.getForDocument(this.selectedSticker), (String) null, ImageLocation.getForDocument(thumb, this.selectedSticker), (String) null, "webp", this.stickerSet, 1);
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.stickerPreviewLayout.getLayoutParams();
            layoutParams.topMargin = this.scrollOffsetY;
            this.stickerPreviewLayout.setLayoutParams(layoutParams);
            this.stickerPreviewLayout.setVisibility(0);
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.playTogether(ObjectAnimator.ofFloat(this.stickerPreviewLayout, (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f));
            animatorSet.setDuration(200L);
            animatorSet.start();
            return;
        }
        TLRPC.StickerSetCovered pack = (TLRPC.StickerSetCovered) this.adapter.positionsToSets.get(position);
        if (pack != null) {
            dismiss();
            TLRPC.TL_inputStickerSetID inputStickerSetID = new TLRPC.TL_inputStickerSetID();
            inputStickerSetID.access_hash = pack.set.access_hash;
            inputStickerSetID.id = pack.set.id;
            StickersAlert alert = new StickersAlert(this.parentActivity, this.parentFragment, inputStickerSetID, null, null);
            alert.show();
        }
    }

    static /* synthetic */ boolean lambda$init$7(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$init$8$StickersAlert(View v) {
        this.optionsButton.toggleSubMenu();
    }

    public /* synthetic */ void lambda$init$9$StickersAlert(View v) {
        hidePreview();
    }

    public /* synthetic */ void lambda$init$10$StickersAlert(View v) {
        this.delegate.lambda$onStickerSelected$28$ChatActivityEnterView(this.selectedSticker, this.stickerSet, this.clearsInputField, true, 0);
        dismiss();
    }

    private void updateSendButton() {
        TLRPC.TL_messages_stickerSet tL_messages_stickerSet;
        int size = (int) ((Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) / 2) / AndroidUtilities.density);
        if (this.delegate != null && ((tL_messages_stickerSet = this.stickerSet) == null || !tL_messages_stickerSet.set.masks)) {
            this.previewSendButton.setText(LocaleController.getString("SendSticker", R.string.SendSticker).toUpperCase());
            this.stickerImageView.setLayoutParams(LayoutHelper.createFrame(size, size, 17, 0.0f, 0.0f, 0.0f, 30.0f));
            this.stickerEmojiTextView.setLayoutParams(LayoutHelper.createFrame(size, size, 17, 0.0f, 0.0f, 0.0f, 30.0f));
            this.previewSendButton.setVisibility(0);
            this.previewSendButtonShadow.setVisibility(0);
            return;
        }
        this.previewSendButton.setText(LocaleController.getString("Close", R.string.Close).toUpperCase());
        this.stickerImageView.setLayoutParams(LayoutHelper.createFrame(size, size, 17));
        this.stickerEmojiTextView.setLayoutParams(LayoutHelper.createFrame(size, size, 17));
        this.previewSendButton.setVisibility(8);
        this.previewSendButtonShadow.setVisibility(8);
    }

    public void setInstallDelegate(StickersAlertInstallDelegate stickersAlertInstallDelegate) {
        this.installDelegate = stickersAlertInstallDelegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onSubItemClick(int id) {
        if (this.stickerSet == null) {
            return;
        }
        String stickersUrl = DefaultWebClient.HTTPS_SCHEME + MessagesController.getInstance(this.currentAccount).linkPrefix + "/addstickers/" + this.stickerSet.set.short_name;
        if (id == 1) {
            ShareAlert alert = new ShareAlert(getContext(), null, stickersUrl, false, stickersUrl, false);
            BaseFragment baseFragment = this.parentFragment;
            if (baseFragment != null) {
                baseFragment.showDialog(alert);
                return;
            } else {
                alert.show();
                return;
            }
        }
        if (id == 2) {
            try {
                AndroidUtilities.addToClipboard(stickersUrl);
                ToastUtils.show(R.string.LinkCopied);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    private void updateFields() {
        if (this.titleTextView == null) {
            return;
        }
        if (this.stickerSet != null) {
            SpannableStringBuilder stringBuilder = null;
            try {
                if (this.urlPattern == null) {
                    this.urlPattern = Pattern.compile("@[a-zA-Z\\d_]{1,32}");
                }
                Matcher matcher = this.urlPattern.matcher(this.stickerSet.set.title);
                while (matcher.find()) {
                    if (stringBuilder == null) {
                        stringBuilder = new SpannableStringBuilder(this.stickerSet.set.title);
                        this.titleTextView.setMovementMethod(new LinkMovementMethodMy());
                    }
                    int start = matcher.start();
                    int end = matcher.end();
                    if (this.stickerSet.set.title.charAt(start) != '@') {
                        start++;
                    }
                    URLSpanNoUnderline url = new URLSpanNoUnderline(this.stickerSet.set.title.subSequence(start + 1, end).toString()) { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.8
                        @Override // im.uwrkaxlmjj.ui.components.URLSpanNoUnderline, android.text.style.URLSpan, android.text.style.ClickableSpan
                        public void onClick(View widget) {
                            MessagesController.getInstance(StickersAlert.this.currentAccount).openByUserName(getURL(), StickersAlert.this.parentFragment, 1);
                            StickersAlert.this.dismiss();
                        }
                    };
                    stringBuilder.setSpan(url, start, end, 0);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            this.titleTextView.setText(stringBuilder != null ? stringBuilder : this.stickerSet.set.title);
            if (this.stickerSet.set == null || !MediaDataController.getInstance(this.currentAccount).isStickerPackInstalled(this.stickerSet.set.id)) {
                String text = this.stickerSet.set.masks ? LocaleController.formatString("AddStickersCount", R.string.AddStickersCount, LocaleController.formatPluralString("MasksCount", this.stickerSet.documents.size())).toUpperCase() : LocaleController.formatString("AddStickersCount", R.string.AddStickersCount, LocaleController.formatPluralString("Stickers", this.stickerSet.documents.size())).toUpperCase();
                setButton(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$40uVBVI2lTAWqN0l3DVhQsjOyvU
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$updateFields$13$StickersAlert(view);
                    }
                }, text, Theme.getColor(Theme.key_dialogTextBlue2));
            } else {
                String text2 = this.stickerSet.set.masks ? LocaleController.formatString("RemoveStickersCount", R.string.RemoveStickersCount, LocaleController.formatPluralString("MasksCount", this.stickerSet.documents.size())).toUpperCase() : LocaleController.formatString("RemoveStickersCount", R.string.RemoveStickersCount, LocaleController.formatPluralString("Stickers", this.stickerSet.documents.size())).toUpperCase();
                if (this.stickerSet.set.official) {
                    setButton(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$FToeOhQOP3jl4SiYlNy496YdeLM
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$updateFields$14$StickersAlert(view);
                        }
                    }, text2, Theme.getColor(Theme.key_dialogTextRed));
                } else {
                    setButton(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$dft5kdyPBN5Oh9wh9cchJPDYVvM
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$updateFields$15$StickersAlert(view);
                        }
                    }, text2, Theme.getColor(Theme.key_dialogTextRed));
                }
            }
            this.adapter.notifyDataSetChanged();
            return;
        }
        String text3 = LocaleController.getString("Close", R.string.Close).toUpperCase();
        setButton(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$-DfsRdxMwXJwKXJNW9gWvM84YSk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$updateFields$16$StickersAlert(view);
            }
        }, text3, Theme.getColor(Theme.key_dialogTextBlue2));
    }

    public /* synthetic */ void lambda$updateFields$13$StickersAlert(View v) {
        dismiss();
        StickersAlertInstallDelegate stickersAlertInstallDelegate = this.installDelegate;
        if (stickersAlertInstallDelegate != null) {
            stickersAlertInstallDelegate.onStickerSetInstalled();
        }
        TLRPC.TL_messages_installStickerSet req = new TLRPC.TL_messages_installStickerSet();
        req.stickerset = this.inputStickerSet;
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$ykorg0_golSkKqCDAw2l8tPlrx4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$12$StickersAlert(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$12$StickersAlert(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickersAlert$aQf8I0urjw30ivNhh55JPyCTrIc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$11$StickersAlert(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$11$StickersAlert(TLRPC.TL_error tL_error, TLObject tLObject) {
        try {
            if (tL_error == null) {
                if (tLObject instanceof TLRPC.TL_messages_stickerSetInstallResultArchive) {
                    NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.needReloadArchivedStickers, new Object[0]);
                    if (this.parentFragment != null && this.parentFragment.getParentActivity() != null) {
                        this.parentFragment.showDialog(new StickersArchiveAlert(this.parentFragment.getParentActivity(), this.parentFragment, ((TLRPC.TL_messages_stickerSetInstallResultArchive) tLObject).sets).create());
                    }
                }
            } else {
                ToastUtils.show(R.string.ErrorOccurred);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        MediaDataController.installingStickerSetId = this.stickerSet.set.id;
        MediaDataController.getInstance(this.currentAccount).loadStickers(this.stickerSet.set.masks ? 1 : 0, false, true);
    }

    public /* synthetic */ void lambda$updateFields$14$StickersAlert(View v) {
        StickersAlertInstallDelegate stickersAlertInstallDelegate = this.installDelegate;
        if (stickersAlertInstallDelegate != null) {
            stickersAlertInstallDelegate.onStickerSetUninstalled();
        }
        dismiss();
        MediaDataController.getInstance(this.currentAccount).removeStickersSet(getContext(), this.stickerSet.set, 1, this.parentFragment, true);
    }

    public /* synthetic */ void lambda$updateFields$15$StickersAlert(View v) {
        StickersAlertInstallDelegate stickersAlertInstallDelegate = this.installDelegate;
        if (stickersAlertInstallDelegate != null) {
            stickersAlertInstallDelegate.onStickerSetUninstalled();
        }
        dismiss();
        MediaDataController.getInstance(this.currentAccount).removeStickersSet(getContext(), this.stickerSet.set, 0, this.parentFragment, true);
    }

    public /* synthetic */ void lambda$updateFields$16$StickersAlert(View v) {
        dismiss();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateLayout() {
        if (this.gridView.getChildCount() <= 0) {
            RecyclerListView recyclerListView = this.gridView;
            int paddingTop = recyclerListView.getPaddingTop();
            this.scrollOffsetY = paddingTop;
            recyclerListView.setTopGlowOffset(paddingTop);
            if (this.stickerSetCovereds == null) {
                this.titleTextView.setTranslationY(this.scrollOffsetY);
                this.optionsButton.setTranslationY(this.scrollOffsetY);
                this.shadow[0].setTranslationY(this.scrollOffsetY);
            }
            this.containerView.invalidate();
            return;
        }
        View child = this.gridView.getChildAt(0);
        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.gridView.findContainingViewHolder(child);
        int top = child.getTop();
        int newOffset = 0;
        if (top >= 0 && holder != null && holder.getAdapterPosition() == 0) {
            newOffset = top;
            runShadowAnimation(0, false);
        } else {
            runShadowAnimation(0, true);
        }
        if (this.scrollOffsetY != newOffset) {
            RecyclerListView recyclerListView2 = this.gridView;
            this.scrollOffsetY = newOffset;
            recyclerListView2.setTopGlowOffset(newOffset);
            if (this.stickerSetCovereds == null) {
                this.titleTextView.setTranslationY(this.scrollOffsetY);
                this.optionsButton.setTranslationY(this.scrollOffsetY);
                this.shadow[0].setTranslationY(this.scrollOffsetY);
            }
            this.containerView.invalidate();
        }
    }

    private void hidePreview() {
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(this.stickerPreviewLayout, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
        animatorSet.setDuration(200L);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.9
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                StickersAlert.this.stickerPreviewLayout.setVisibility(8);
            }
        });
        animatorSet.start();
    }

    private void runShadowAnimation(final int num, final boolean show) {
        if (this.stickerSetCovereds != null) {
            return;
        }
        if ((show && this.shadow[num].getTag() != null) || (!show && this.shadow[num].getTag() == null)) {
            this.shadow[num].setTag(show ? null : 1);
            if (show) {
                this.shadow[num].setVisibility(0);
            }
            AnimatorSet[] animatorSetArr = this.shadowAnimation;
            if (animatorSetArr[num] != null) {
                animatorSetArr[num].cancel();
            }
            this.shadowAnimation[num] = new AnimatorSet();
            AnimatorSet animatorSet = this.shadowAnimation[num];
            Animator[] animatorArr = new Animator[1];
            View view = this.shadow[num];
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(view, (Property<View, Float>) property, fArr);
            animatorSet.playTogether(animatorArr);
            this.shadowAnimation[num].setDuration(150L);
            this.shadowAnimation[num].addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.10
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (StickersAlert.this.shadowAnimation[num] != null && StickersAlert.this.shadowAnimation[num].equals(animation)) {
                        if (!show) {
                            StickersAlert.this.shadow[num].setVisibility(4);
                        }
                        StickersAlert.this.shadowAnimation[num] = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (StickersAlert.this.shadowAnimation[num] != null && StickersAlert.this.shadowAnimation[num].equals(animation)) {
                        StickersAlert.this.shadowAnimation[num] = null;
                    }
                }
            });
            this.shadowAnimation[num].start();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        super.dismiss();
        if (this.reqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.reqId, true);
            this.reqId = 0;
        }
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 2);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.emojiDidLoad) {
            RecyclerListView recyclerListView = this.gridView;
            if (recyclerListView != null) {
                int count = recyclerListView.getChildCount();
                for (int a = 0; a < count; a++) {
                    this.gridView.getChildAt(a).invalidate();
                }
            }
            if (ContentPreviewViewer.getInstance().isVisible()) {
                ContentPreviewViewer.getInstance().close();
            }
            ContentPreviewViewer.getInstance().reset();
        }
    }

    private void setButton(View.OnClickListener onClickListener, String title, int color) {
        this.pickerBottomLayout.setTextColor(color);
        this.pickerBottomLayout.setText(title.toUpperCase());
        this.pickerBottomLayout.setOnClickListener(onClickListener);
    }

    private class GridAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private int stickersPerRow;
        private int stickersRowCount;
        private int totalItems;
        private SparseArray<Object> cache = new SparseArray<>();
        private SparseArray<TLRPC.StickerSetCovered> positionsToSets = new SparseArray<>();

        public GridAdapter(Context context) {
            this.context = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.totalItems;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (StickersAlert.this.stickerSetCovereds == null) {
                return 0;
            }
            Object object = this.cache.get(position);
            if (object != null) {
                return object instanceof TLRPC.Document ? 0 : 2;
            }
            return 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                StickerEmojiCell cell = new StickerEmojiCell(this.context) { // from class: im.uwrkaxlmjj.ui.components.StickersAlert.GridAdapter.1
                    @Override // android.widget.FrameLayout, android.view.View
                    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(View.MeasureSpec.makeMeasureSpec(StickersAlert.this.itemSize, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(82.0f), 1073741824));
                    }
                };
                cell.getImageView().setLayerNum(3);
                view = cell;
            } else if (viewType == 1) {
                view = new EmptyCell(this.context);
            } else if (viewType == 2) {
                view = new FeaturedStickerSetInfoCell(this.context, 8);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (StickersAlert.this.stickerSetCovereds == null) {
                ((StickerEmojiCell) holder.itemView).setSticker(StickersAlert.this.stickerSet.documents.get(position), StickersAlert.this.stickerSet, StickersAlert.this.showEmoji);
                return;
            }
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                TLRPC.Document sticker = (TLRPC.Document) this.cache.get(position);
                ((StickerEmojiCell) holder.itemView).setSticker(sticker, this.positionsToSets.get(position), false);
            } else if (itemViewType == 1) {
                ((EmptyCell) holder.itemView).setHeight(AndroidUtilities.dp(82.0f));
            } else if (itemViewType == 2) {
                TLRPC.StickerSetCovered stickerSetCovered = (TLRPC.StickerSetCovered) StickersAlert.this.stickerSetCovereds.get(((Integer) this.cache.get(position)).intValue());
                FeaturedStickerSetInfoCell cell = (FeaturedStickerSetInfoCell) holder.itemView;
                cell.setStickerSet(stickerSetCovered, false);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            int count;
            int i;
            if (StickersAlert.this.stickerSetCovereds != null) {
                int width = StickersAlert.this.gridView.getMeasuredWidth();
                if (width == 0) {
                    width = AndroidUtilities.displaySize.x;
                }
                this.stickersPerRow = width / AndroidUtilities.dp(72.0f);
                StickersAlert.this.layoutManager.setSpanCount(this.stickersPerRow);
                this.cache.clear();
                this.positionsToSets.clear();
                this.totalItems = 0;
                this.stickersRowCount = 0;
                for (int a = 0; a < StickersAlert.this.stickerSetCovereds.size(); a++) {
                    TLRPC.StickerSetCovered pack = (TLRPC.StickerSetCovered) StickersAlert.this.stickerSetCovereds.get(a);
                    if (!pack.covers.isEmpty() || pack.cover != null) {
                        this.stickersRowCount = (int) (((double) this.stickersRowCount) + Math.ceil(StickersAlert.this.stickerSetCovereds.size() / this.stickersPerRow));
                        this.positionsToSets.put(this.totalItems, pack);
                        SparseArray<Object> sparseArray = this.cache;
                        int i2 = this.totalItems;
                        this.totalItems = i2 + 1;
                        sparseArray.put(i2, Integer.valueOf(a));
                        int i3 = this.totalItems / this.stickersPerRow;
                        if (!pack.covers.isEmpty()) {
                            count = (int) Math.ceil(pack.covers.size() / this.stickersPerRow);
                            for (int b = 0; b < pack.covers.size(); b++) {
                                this.cache.put(this.totalItems + b, pack.covers.get(b));
                            }
                        } else {
                            count = 1;
                            this.cache.put(this.totalItems, pack.cover);
                        }
                        int b2 = 0;
                        while (true) {
                            i = this.stickersPerRow;
                            if (b2 >= count * i) {
                                break;
                            }
                            this.positionsToSets.put(this.totalItems + b2, pack);
                            b2++;
                        }
                        int b3 = this.totalItems;
                        this.totalItems = b3 + (i * count);
                    }
                }
            } else {
                this.totalItems = StickersAlert.this.stickerSet != null ? StickersAlert.this.stickerSet.documents.size() : 0;
            }
            super.notifyDataSetChanged();
        }
    }
}
