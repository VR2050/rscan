package im.uwrkaxlmjj.ui;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.FrameLayout;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.WebFile;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ContentPreviewViewer;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.ContextLinkCell;
import im.uwrkaxlmjj.ui.cells.StickerCell;
import im.uwrkaxlmjj.ui.cells.StickerEmojiCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ContentPreviewViewer {
    private static final int CONTENT_TYPE_GIF = 1;
    private static final int CONTENT_TYPE_NONE = -1;
    private static final int CONTENT_TYPE_STICKER = 0;
    private static volatile ContentPreviewViewer Instance = null;
    private static TextPaint textPaint;
    private boolean animateY;
    private boolean clearsInputField;
    private FrameLayoutDrawer containerView;
    private int currentAccount;
    private int currentContentType;
    private TLRPC.Document currentDocument;
    private float currentMoveY;
    private float currentMoveYProgress;
    private View currentPreviewCell;
    private TLRPC.InputStickerSet currentStickerSet;
    private ContentPreviewViewerDelegate delegate;
    private float finalMoveY;
    private TLRPC.BotInlineResult inlineResult;
    private WindowInsets lastInsets;
    private float lastTouchY;
    private long lastUpdateTime;
    private Runnable openPreviewRunnable;
    private Activity parentActivity;
    private Object parentObject;
    private float showProgress;
    private Drawable slideUpDrawable;
    private float startMoveY;
    private int startX;
    private int startY;
    private StaticLayout stickerEmojiLayout;
    private BottomSheet visibleDialog;
    private WindowManager.LayoutParams windowLayoutParams;
    private FrameLayout windowView;
    private float moveY = 0.0f;
    private ColorDrawable backgroundDrawable = new ColorDrawable(1895825408);
    private ImageReceiver centerImage = new ImageReceiver();
    private boolean isVisible = false;
    private int keyboardHeight = AndroidUtilities.dp(200.0f);
    private Runnable showSheetRunnable = new AnonymousClass1();

    private class FrameLayoutDrawer extends FrameLayout {
        public FrameLayoutDrawer(Context context) {
            super(context);
            setWillNotDraw(false);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            ContentPreviewViewer.this.onDraw(canvas);
        }
    }

    public interface ContentPreviewViewerDelegate {
        boolean canSchedule();

        void gifAddedOrDeleted();

        boolean isInScheduleMode();

        boolean needOpen();

        boolean needSend();

        void openSet(TLRPC.InputStickerSet inputStickerSet, boolean z);

        void sendGif(Object obj, boolean z, int i);

        void sendSticker(TLRPC.Document document, Object obj, boolean z, int i);

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ContentPreviewViewer$ContentPreviewViewerDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static boolean $default$needOpen(ContentPreviewViewerDelegate _this) {
                return true;
            }

            public static void $default$sendGif(ContentPreviewViewerDelegate _this, Object gif, boolean notify, int scheduleDate) {
            }

            public static void $default$gifAddedOrDeleted(ContentPreviewViewerDelegate _this) {
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ContentPreviewViewer$1, reason: invalid class name */
    class AnonymousClass1 implements Runnable {
        AnonymousClass1() {
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // java.lang.Runnable
        public void run() {
            boolean z;
            int i;
            String str;
            if (ContentPreviewViewer.this.parentActivity != null) {
                boolean z2 = false;
                if (ContentPreviewViewer.this.currentContentType == 0) {
                    final boolean zIsStickerInFavorites = MediaDataController.getInstance(ContentPreviewViewer.this.currentAccount).isStickerInFavorites(ContentPreviewViewer.this.currentDocument);
                    BottomSheet.Builder builder = new BottomSheet.Builder(ContentPreviewViewer.this.parentActivity);
                    ArrayList arrayList = new ArrayList();
                    final ArrayList arrayList2 = new ArrayList();
                    ArrayList arrayList3 = new ArrayList();
                    if (ContentPreviewViewer.this.delegate != null) {
                        if (ContentPreviewViewer.this.delegate.needSend() && !ContentPreviewViewer.this.delegate.isInScheduleMode()) {
                            arrayList.add(LocaleController.getString("SendStickerPreview", R.string.SendStickerPreview));
                            arrayList3.add(Integer.valueOf(R.drawable.outline_send));
                            arrayList2.add(0);
                        }
                        if (ContentPreviewViewer.this.delegate.canSchedule()) {
                            arrayList.add(LocaleController.getString("Schedule", R.string.Schedule));
                            arrayList3.add(Integer.valueOf(R.drawable.photo_timer));
                            arrayList2.add(3);
                        }
                        if (ContentPreviewViewer.this.currentStickerSet != null && ContentPreviewViewer.this.delegate.needOpen()) {
                            arrayList.add(LocaleController.formatString("ViewPackPreview", R.string.ViewPackPreview, new Object[0]));
                            arrayList3.add(Integer.valueOf(R.drawable.outline_pack));
                            arrayList2.add(1);
                        }
                    }
                    if (!MessageObject.isMaskDocument(ContentPreviewViewer.this.currentDocument) && (zIsStickerInFavorites || MediaDataController.getInstance(ContentPreviewViewer.this.currentAccount).canAddStickerToFavorites())) {
                        if (zIsStickerInFavorites) {
                            i = R.string.DeleteFromFavorites;
                            str = "DeleteFromFavorites";
                        } else {
                            i = R.string.AddToFavorites;
                            str = "AddToFavorites";
                        }
                        arrayList.add(LocaleController.getString(str, i));
                        arrayList3.add(Integer.valueOf(zIsStickerInFavorites ? R.drawable.outline_unfave : R.drawable.outline_fave));
                        arrayList2.add(2);
                    }
                    if (arrayList.isEmpty()) {
                        return;
                    }
                    int[] iArr = new int[arrayList3.size()];
                    for (int i2 = 0; i2 < arrayList3.size(); i2++) {
                        iArr[i2] = ((Integer) arrayList3.get(i2)).intValue();
                    }
                    builder.setItems((CharSequence[]) arrayList.toArray(new CharSequence[0]), iArr, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$1$PQFWsnvvVHZS4jcX2EqNWOI2EzA
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i3) {
                            this.f$0.lambda$run$1$ContentPreviewViewer$1(arrayList2, zIsStickerInFavorites, dialogInterface, i3);
                        }
                    });
                    builder.setDimBehind(false);
                    ContentPreviewViewer.this.visibleDialog = builder.create();
                    ContentPreviewViewer.this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$1$VblnLvcYxrTjPyAEOORvV9GxO4A
                        @Override // android.content.DialogInterface.OnDismissListener
                        public final void onDismiss(DialogInterface dialogInterface) {
                            this.f$0.lambda$run$2$ContentPreviewViewer$1(dialogInterface);
                        }
                    });
                    ContentPreviewViewer.this.visibleDialog.show();
                    ContentPreviewViewer.this.containerView.performHapticFeedback(0);
                    return;
                }
                if (ContentPreviewViewer.this.delegate != null) {
                    ContentPreviewViewer.this.animateY = true;
                    ContentPreviewViewer.this.visibleDialog = new BottomSheet(ContentPreviewViewer.this.parentActivity, z2, null == true ? 1 : 0) { // from class: im.uwrkaxlmjj.ui.ContentPreviewViewer.1.1
                        @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
                        protected void onContainerTranslationYChanged(float translationY) {
                            if (ContentPreviewViewer.this.animateY) {
                                getSheetContainer();
                                if (ContentPreviewViewer.this.finalMoveY == 0.0f) {
                                    ContentPreviewViewer.this.finalMoveY = 0.0f;
                                    ContentPreviewViewer.this.startMoveY = ContentPreviewViewer.this.moveY;
                                }
                                ContentPreviewViewer.this.currentMoveYProgress = 1.0f - Math.min(1.0f, translationY / this.containerView.getMeasuredHeight());
                                ContentPreviewViewer.this.moveY = ContentPreviewViewer.this.startMoveY + ((ContentPreviewViewer.this.finalMoveY - ContentPreviewViewer.this.startMoveY) * ContentPreviewViewer.this.currentMoveYProgress);
                                ContentPreviewViewer.this.containerView.invalidate();
                                if (ContentPreviewViewer.this.currentMoveYProgress == 1.0f) {
                                    ContentPreviewViewer.this.animateY = false;
                                }
                            }
                        }
                    };
                    ArrayList arrayList4 = new ArrayList();
                    final ArrayList arrayList5 = new ArrayList();
                    ArrayList arrayList6 = new ArrayList();
                    if (ContentPreviewViewer.this.delegate.needSend() && !ContentPreviewViewer.this.delegate.isInScheduleMode()) {
                        arrayList4.add(LocaleController.getString("SendGifPreview", R.string.SendGifPreview));
                        arrayList6.add(Integer.valueOf(R.drawable.outline_send));
                        arrayList5.add(0);
                    }
                    if (ContentPreviewViewer.this.delegate.canSchedule()) {
                        arrayList4.add(LocaleController.getString("Schedule", R.string.Schedule));
                        arrayList6.add(Integer.valueOf(R.drawable.photo_timer));
                        arrayList5.add(3);
                    }
                    if (ContentPreviewViewer.this.currentDocument != null) {
                        boolean zHasRecentGif = MediaDataController.getInstance(ContentPreviewViewer.this.currentAccount).hasRecentGif(ContentPreviewViewer.this.currentDocument);
                        z = zHasRecentGif;
                        if (zHasRecentGif) {
                            arrayList4.add(LocaleController.formatString("Delete", R.string.Delete, new Object[0]));
                            arrayList6.add(Integer.valueOf(R.drawable.chats_delete));
                            arrayList5.add(1);
                        } else {
                            arrayList4.add(LocaleController.formatString("SaveToGIFs", R.string.SaveToGIFs, new Object[0]));
                            arrayList6.add(Integer.valueOf(R.drawable.outline_add_gif));
                            arrayList5.add(2);
                        }
                    } else {
                        z = false;
                    }
                    int[] iArr2 = new int[arrayList6.size()];
                    for (int i3 = 0; i3 < arrayList6.size(); i3++) {
                        iArr2[i3] = ((Integer) arrayList6.get(i3)).intValue();
                    }
                    ContentPreviewViewer.this.visibleDialog.setItems((CharSequence[]) arrayList4.toArray(new CharSequence[0]), iArr2, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$1$yw091MeGIkBdxClkD9jcgH6g6KU
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i4) {
                            this.f$0.lambda$run$4$ContentPreviewViewer$1(arrayList5, dialogInterface, i4);
                        }
                    });
                    ContentPreviewViewer.this.visibleDialog.setDimBehind(false);
                    ContentPreviewViewer.this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$1$AvlDc-oh3e9zKCr5PMU0a-IDS_Y
                        @Override // android.content.DialogInterface.OnDismissListener
                        public final void onDismiss(DialogInterface dialogInterface) {
                            this.f$0.lambda$run$5$ContentPreviewViewer$1(dialogInterface);
                        }
                    });
                    ContentPreviewViewer.this.visibleDialog.show();
                    ContentPreviewViewer.this.containerView.performHapticFeedback(0);
                    if (z) {
                        ContentPreviewViewer.this.visibleDialog.setItemColor(arrayList4.size() - 1, Theme.getColor(Theme.key_dialogTextRed2), Theme.getColor(Theme.key_dialogRedIcon));
                    }
                }
            }
        }

        public /* synthetic */ void lambda$run$1$ContentPreviewViewer$1(ArrayList actions, boolean inFavs, DialogInterface dialog, int which) {
            if (ContentPreviewViewer.this.parentActivity == null) {
                return;
            }
            if (((Integer) actions.get(which)).intValue() == 0) {
                if (ContentPreviewViewer.this.delegate != null) {
                    ContentPreviewViewer.this.delegate.sendSticker(ContentPreviewViewer.this.currentDocument, ContentPreviewViewer.this.parentObject, true, 0);
                }
            } else if (((Integer) actions.get(which)).intValue() == 1) {
                if (ContentPreviewViewer.this.delegate != null) {
                    ContentPreviewViewer.this.delegate.openSet(ContentPreviewViewer.this.currentStickerSet, ContentPreviewViewer.this.clearsInputField);
                }
            } else if (((Integer) actions.get(which)).intValue() == 2) {
                MediaDataController.getInstance(ContentPreviewViewer.this.currentAccount).addRecentSticker(2, ContentPreviewViewer.this.parentObject, ContentPreviewViewer.this.currentDocument, (int) (System.currentTimeMillis() / 1000), inFavs);
            } else if (((Integer) actions.get(which)).intValue() == 3) {
                final TLRPC.Document sticker = ContentPreviewViewer.this.currentDocument;
                final Object parent = ContentPreviewViewer.this.parentObject;
                final ContentPreviewViewerDelegate stickerPreviewViewerDelegate = ContentPreviewViewer.this.delegate;
                AlertsCreator.createScheduleDatePickerDialog(ContentPreviewViewer.this.parentActivity, false, new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$1$DK6ESDPkK-vx_ilQdHruXV6KTSg
                    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                    public final void didSelectDate(boolean z, int i) {
                        stickerPreviewViewerDelegate.sendSticker(sticker, parent, z, i);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$run$2$ContentPreviewViewer$1(DialogInterface dialog) {
            ContentPreviewViewer.this.visibleDialog = null;
            ContentPreviewViewer.this.close();
        }

        public /* synthetic */ void lambda$run$4$ContentPreviewViewer$1(ArrayList actions, DialogInterface dialog, int which) {
            if (ContentPreviewViewer.this.parentActivity == null) {
                return;
            }
            if (((Integer) actions.get(which)).intValue() == 0) {
                ContentPreviewViewer.this.delegate.sendGif(ContentPreviewViewer.this.currentDocument != null ? ContentPreviewViewer.this.currentDocument : ContentPreviewViewer.this.inlineResult, true, 0);
                return;
            }
            if (((Integer) actions.get(which)).intValue() == 1) {
                MediaDataController.getInstance(ContentPreviewViewer.this.currentAccount).removeRecentGif(ContentPreviewViewer.this.currentDocument);
                ContentPreviewViewer.this.delegate.gifAddedOrDeleted();
                return;
            }
            if (((Integer) actions.get(which)).intValue() == 2) {
                MediaDataController.getInstance(ContentPreviewViewer.this.currentAccount).addRecentGif(ContentPreviewViewer.this.currentDocument, (int) (System.currentTimeMillis() / 1000));
                MessagesController.getInstance(ContentPreviewViewer.this.currentAccount).saveGif("gif", ContentPreviewViewer.this.currentDocument);
                ContentPreviewViewer.this.delegate.gifAddedOrDeleted();
            } else if (((Integer) actions.get(which)).intValue() == 3) {
                final TLRPC.Document document = ContentPreviewViewer.this.currentDocument;
                final TLRPC.BotInlineResult result = ContentPreviewViewer.this.inlineResult;
                Object unused = ContentPreviewViewer.this.parentObject;
                final ContentPreviewViewerDelegate stickerPreviewViewerDelegate = ContentPreviewViewer.this.delegate;
                AlertsCreator.createScheduleDatePickerDialog(ContentPreviewViewer.this.parentActivity, false, new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$1$cUj5UwkG0NSceZgiWlIQpT4pfrI
                    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                    public final void didSelectDate(boolean z, int i) {
                        ContentPreviewViewer.ContentPreviewViewerDelegate contentPreviewViewerDelegate = stickerPreviewViewerDelegate;
                        TLRPC.Document document2 = document;
                        contentPreviewViewerDelegate.sendGif(document2 != null ? document2 : result, z, i);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$run$5$ContentPreviewViewer$1(DialogInterface dialog) {
            ContentPreviewViewer.this.visibleDialog = null;
            ContentPreviewViewer.this.close();
        }
    }

    public static ContentPreviewViewer getInstance() {
        ContentPreviewViewer localInstance = Instance;
        if (localInstance == null) {
            synchronized (PhotoViewer.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    ContentPreviewViewer contentPreviewViewer = new ContentPreviewViewer();
                    localInstance = contentPreviewViewer;
                    Instance = contentPreviewViewer;
                }
            }
        }
        return localInstance;
    }

    public static boolean hasInstance() {
        return Instance != null;
    }

    public void reset() {
        Runnable runnable = this.openPreviewRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.openPreviewRunnable = null;
        }
        View view = this.currentPreviewCell;
        if (view != null) {
            if (view instanceof StickerEmojiCell) {
                ((StickerEmojiCell) view).setScaled(false);
            } else if (view instanceof StickerCell) {
                ((StickerCell) view).setScaled(false);
            } else if (view instanceof ContextLinkCell) {
                ((ContextLinkCell) view).setScaled(false);
            }
            this.currentPreviewCell = null;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:69:0x013b  */
    /* JADX WARN: Type inference failed for: r1v0 */
    /* JADX WARN: Type inference failed for: r1v8, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r1v9 */
    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouch(android.view.MotionEvent r23, final im.uwrkaxlmjj.ui.components.RecyclerListView r24, int r25, final java.lang.Object r26, im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate r27) {
        /*
            Method dump skipped, instruction units count: 653
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ContentPreviewViewer.onTouch(android.view.MotionEvent, im.uwrkaxlmjj.ui.components.RecyclerListView, int, java.lang.Object, im.uwrkaxlmjj.ui.ContentPreviewViewer$ContentPreviewViewerDelegate):boolean");
    }

    static /* synthetic */ void lambda$onTouch$0(RecyclerListView listView, Object listener) {
        if (listView instanceof RecyclerListView) {
            listView.setOnItemClickListener((RecyclerListView.OnItemClickListener) listener);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    public boolean onInterceptTouchEvent(MotionEvent event, RecyclerListView listView, final int height, ContentPreviewViewerDelegate contentPreviewViewerDelegate) {
        final ContentPreviewViewer contentPreviewViewer = this;
        final RecyclerListView recyclerListView = listView;
        contentPreviewViewer.delegate = contentPreviewViewerDelegate;
        ?? r4 = 0;
        if (event.getAction() == 0) {
            int x = (int) event.getX();
            int y = (int) event.getY();
            int count = listView.getChildCount();
            int a = 0;
            while (a < count) {
                View view = null;
                if (recyclerListView instanceof RecyclerListView) {
                    view = recyclerListView.getChildAt(a);
                }
                if (view == null) {
                    return r4;
                }
                int top = view.getTop();
                int bottom = view.getBottom();
                int left = view.getLeft();
                int right = view.getRight();
                if (top > y || bottom < y || left > x || right < x) {
                    a++;
                    r4 = 0;
                    contentPreviewViewer = this;
                    recyclerListView = listView;
                } else {
                    int contentType = -1;
                    if (view instanceof StickerEmojiCell) {
                        if (((StickerEmojiCell) view).showingBitmap()) {
                            contentType = 0;
                            contentPreviewViewer.centerImage.setRoundRadius(r4);
                        }
                    } else if (view instanceof StickerCell) {
                        if (((StickerCell) view).showingBitmap()) {
                            contentType = 0;
                            contentPreviewViewer.centerImage.setRoundRadius(r4);
                        }
                    } else if (view instanceof ContextLinkCell) {
                        ContextLinkCell cell = (ContextLinkCell) view;
                        if (cell.showingBitmap()) {
                            if (cell.isSticker()) {
                                contentType = 0;
                                contentPreviewViewer.centerImage.setRoundRadius(r4);
                            } else if (cell.isGif()) {
                                contentType = 1;
                                contentPreviewViewer.centerImage.setRoundRadius(AndroidUtilities.dp(6.0f));
                            }
                        }
                    }
                    if (contentType == -1) {
                        return false;
                    }
                    contentPreviewViewer.startX = x;
                    contentPreviewViewer.startY = y;
                    contentPreviewViewer.currentPreviewCell = view;
                    final int contentTypeFinal = contentType;
                    Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$VXzDoaBYBZxg-qscweQWdpFrm5E
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onInterceptTouchEvent$1$ContentPreviewViewer(recyclerListView, height, contentTypeFinal);
                        }
                    };
                    contentPreviewViewer.openPreviewRunnable = runnable;
                    AndroidUtilities.runOnUIThread(runnable, 200L);
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    public /* synthetic */ void lambda$onInterceptTouchEvent$1$ContentPreviewViewer(RecyclerListView listView, int height, int contentTypeFinal) {
        if (this.openPreviewRunnable == null) {
            return;
        }
        listView.setOnItemClickListener((RecyclerListView.OnItemClickListener) null);
        listView.requestDisallowInterceptTouchEvent(true);
        this.openPreviewRunnable = null;
        setParentActivity((Activity) listView.getContext());
        setKeyboardHeight(height);
        this.clearsInputField = false;
        View view = this.currentPreviewCell;
        if (view instanceof StickerEmojiCell) {
            StickerEmojiCell stickerEmojiCell = (StickerEmojiCell) view;
            open(stickerEmojiCell.getSticker(), null, contentTypeFinal, stickerEmojiCell.isRecent(), stickerEmojiCell.getParentObject());
            stickerEmojiCell.setScaled(true);
        } else {
            if (view instanceof StickerCell) {
                StickerCell stickerCell = (StickerCell) view;
                open(stickerCell.getSticker(), null, contentTypeFinal, false, stickerCell.getParentObject());
                stickerCell.setScaled(true);
                this.clearsInputField = stickerCell.isClearsInputField();
                return;
            }
            if (view instanceof ContextLinkCell) {
                ContextLinkCell contextLinkCell = (ContextLinkCell) view;
                open(contextLinkCell.getDocument(), contextLinkCell.getBotInlineResult(), contentTypeFinal, false, null);
                if (contentTypeFinal != 1) {
                    contextLinkCell.setScaled(true);
                }
            }
        }
    }

    public void setDelegate(ContentPreviewViewerDelegate contentPreviewViewerDelegate) {
        this.delegate = contentPreviewViewerDelegate;
    }

    public void setParentActivity(Activity activity) {
        int i = UserConfig.selectedAccount;
        this.currentAccount = i;
        this.centerImage.setCurrentAccount(i);
        this.centerImage.setLayerNum(7);
        if (this.parentActivity == activity) {
            return;
        }
        this.parentActivity = activity;
        this.slideUpDrawable = activity.getResources().getDrawable(R.drawable.preview_arrow);
        FrameLayout frameLayout = new FrameLayout(activity);
        this.windowView = frameLayout;
        frameLayout.setFocusable(true);
        this.windowView.setFocusableInTouchMode(true);
        if (Build.VERSION.SDK_INT >= 21) {
            this.windowView.setFitsSystemWindows(true);
            this.windowView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$J5Vj1m0nJBfXG_vDRorSbak33Zo
                @Override // android.view.View.OnApplyWindowInsetsListener
                public final WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
                    return this.f$0.lambda$setParentActivity$2$ContentPreviewViewer(view, windowInsets);
                }
            });
        }
        FrameLayoutDrawer frameLayoutDrawer = new FrameLayoutDrawer(activity);
        this.containerView = frameLayoutDrawer;
        frameLayoutDrawer.setFocusable(false);
        this.windowView.addView(this.containerView, LayoutHelper.createFrame(-1, -1, 51));
        this.containerView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$TJQfsNQjJcLo_wEhd4gMqL0TTrg
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return this.f$0.lambda$setParentActivity$3$ContentPreviewViewer(view, motionEvent);
            }
        });
        WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
        this.windowLayoutParams = layoutParams;
        layoutParams.height = -1;
        this.windowLayoutParams.format = -3;
        this.windowLayoutParams.width = -1;
        this.windowLayoutParams.gravity = 48;
        this.windowLayoutParams.type = 99;
        if (Build.VERSION.SDK_INT >= 21) {
            this.windowLayoutParams.flags = -2147417848;
        } else {
            this.windowLayoutParams.flags = 8;
        }
        this.centerImage.setAspectFit(true);
        this.centerImage.setInvalidateAll(true);
        this.centerImage.setParentView(this.containerView);
    }

    public /* synthetic */ WindowInsets lambda$setParentActivity$2$ContentPreviewViewer(View v, WindowInsets insets) {
        this.lastInsets = insets;
        return insets;
    }

    public /* synthetic */ boolean lambda$setParentActivity$3$ContentPreviewViewer(View v, MotionEvent event) {
        if (event.getAction() == 1 || event.getAction() == 6 || event.getAction() == 3) {
            close();
        }
        return true;
    }

    public void setKeyboardHeight(int height) {
        this.keyboardHeight = height;
    }

    public void open(TLRPC.Document document, TLRPC.BotInlineResult botInlineResult, int contentType, boolean isRecent, Object parent) {
        if (this.parentActivity != null && this.windowView != null) {
            this.stickerEmojiLayout = null;
            if (contentType == 0) {
                if (document == null) {
                    return;
                }
                if (textPaint == null) {
                    TextPaint textPaint2 = new TextPaint(1);
                    textPaint = textPaint2;
                    textPaint2.setTextSize(AndroidUtilities.dp(24.0f));
                }
                TLRPC.InputStickerSet newSet = null;
                int a = 0;
                while (true) {
                    if (a >= document.attributes.size()) {
                        break;
                    }
                    TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                    if (!(attribute instanceof TLRPC.TL_documentAttributeSticker) || attribute.stickerset == null) {
                        a++;
                    } else {
                        newSet = attribute.stickerset;
                        break;
                    }
                }
                if (newSet != null) {
                    try {
                        if (this.visibleDialog != null) {
                            this.visibleDialog.setOnDismissListener(null);
                            this.visibleDialog.dismiss();
                            this.visibleDialog = null;
                        }
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                    AndroidUtilities.cancelRunOnUIThread(this.showSheetRunnable);
                    AndroidUtilities.runOnUIThread(this.showSheetRunnable, 1300L);
                }
                this.currentStickerSet = newSet;
                this.parentObject = parent;
                TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90);
                this.centerImage.setImage(ImageLocation.getForDocument(document), (String) null, ImageLocation.getForDocument(thumb, document), (String) null, "webp", this.currentStickerSet, 1);
                int a2 = 0;
                while (true) {
                    if (a2 >= document.attributes.size()) {
                        break;
                    }
                    TLRPC.DocumentAttribute attribute2 = document.attributes.get(a2);
                    if ((attribute2 instanceof TLRPC.TL_documentAttributeSticker) && !TextUtils.isEmpty(attribute2.alt)) {
                        CharSequence emoji = Emoji.replaceEmoji(attribute2.alt, textPaint.getFontMetricsInt(), AndroidUtilities.dp(24.0f), false);
                        this.stickerEmojiLayout = new StaticLayout(emoji, textPaint, AndroidUtilities.dp(100.0f), Layout.Alignment.ALIGN_CENTER, 1.0f, 0.0f, false);
                        break;
                    }
                    a2++;
                }
            } else {
                if (document != null) {
                    TLRPC.PhotoSize thumb2 = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90);
                    this.centerImage.setImage(ImageLocation.getForDocument(document), null, ImageLocation.getForDocument(thumb2, document), "90_90_b", document.size, null, "gif" + document, 0);
                } else {
                    if (botInlineResult == null || botInlineResult.content == null) {
                        return;
                    }
                    this.centerImage.setImage(ImageLocation.getForWebFile(WebFile.createWithWebDocument(botInlineResult.content)), null, ImageLocation.getForWebFile(WebFile.createWithWebDocument(botInlineResult.thumb)), "90_90_b", botInlineResult.content.size, null, "gif" + botInlineResult, 1);
                }
                AndroidUtilities.cancelRunOnUIThread(this.showSheetRunnable);
                AndroidUtilities.runOnUIThread(this.showSheetRunnable, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            }
            this.currentContentType = contentType;
            this.currentDocument = document;
            this.inlineResult = botInlineResult;
            this.containerView.invalidate();
            if (!this.isVisible) {
                AndroidUtilities.lockOrientation(this.parentActivity);
                try {
                    if (this.windowView.getParent() != null) {
                        WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                        wm.removeView(this.windowView);
                    }
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
                WindowManager wm2 = (WindowManager) this.parentActivity.getSystemService("window");
                wm2.addView(this.windowView, this.windowLayoutParams);
                this.isVisible = true;
                this.showProgress = 0.0f;
                this.lastTouchY = -10000.0f;
                this.currentMoveYProgress = 0.0f;
                this.finalMoveY = 0.0f;
                this.currentMoveY = 0.0f;
                this.moveY = 0.0f;
                this.lastUpdateTime = System.currentTimeMillis();
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 4);
            }
        }
    }

    public boolean isVisible() {
        return this.isVisible;
    }

    public void close() {
        if (this.parentActivity == null || this.visibleDialog != null) {
            return;
        }
        AndroidUtilities.cancelRunOnUIThread(this.showSheetRunnable);
        this.showProgress = 1.0f;
        this.lastUpdateTime = System.currentTimeMillis();
        this.containerView.invalidate();
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        this.currentDocument = null;
        this.currentStickerSet = null;
        this.delegate = null;
        this.isVisible = false;
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 4);
    }

    public void destroy() {
        FrameLayout frameLayout;
        this.isVisible = false;
        this.delegate = null;
        this.currentDocument = null;
        this.currentStickerSet = null;
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (this.parentActivity == null || (frameLayout = this.windowView) == null) {
            return;
        }
        try {
            if (frameLayout.getParent() != null) {
                WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                wm.removeViewImmediate(this.windowView);
            }
            this.windowView = null;
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        Instance = null;
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 4);
    }

    private float rubberYPoisition(float offset, float factor) {
        float delta = Math.abs(offset);
        return (-((1.0f - (1.0f / (((0.55f * delta) / factor) + 1.0f))) * factor)) * (offset >= 0.0f ? -1.0f : 1.0f);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onDraw(Canvas canvas) {
        ColorDrawable colorDrawable;
        int top;
        int size;
        Drawable drawable;
        WindowInsets windowInsets;
        if (this.containerView == null || (colorDrawable = this.backgroundDrawable) == null) {
            return;
        }
        colorDrawable.setAlpha((int) (this.showProgress * 180.0f));
        this.backgroundDrawable.setBounds(0, 0, this.containerView.getWidth(), this.containerView.getHeight());
        this.backgroundDrawable.draw(canvas);
        canvas.save();
        int insets = 0;
        if (Build.VERSION.SDK_INT >= 21 && (windowInsets = this.lastInsets) != null) {
            insets = windowInsets.getStableInsetBottom() + this.lastInsets.getStableInsetTop();
            top = this.lastInsets.getStableInsetTop();
        } else {
            top = AndroidUtilities.statusBarHeight;
        }
        if (this.currentContentType == 1) {
            size = Math.min(this.containerView.getWidth(), this.containerView.getHeight() - insets) - AndroidUtilities.dp(40.0f);
        } else {
            size = (int) (Math.min(this.containerView.getWidth(), this.containerView.getHeight() - insets) / 1.8f);
        }
        canvas.translate(this.containerView.getWidth() / 2, this.moveY + Math.max((size / 2) + top + (this.stickerEmojiLayout != null ? AndroidUtilities.dp(40.0f) : 0), ((this.containerView.getHeight() - insets) - this.keyboardHeight) / 2));
        float f = this.showProgress;
        float scale = (f * 0.8f) / 0.8f;
        int size2 = (int) (size * scale);
        this.centerImage.setAlpha(f);
        this.centerImage.setImageCoords((-size2) / 2, (-size2) / 2, size2, size2);
        this.centerImage.draw(canvas);
        if (this.currentContentType == 1 && (drawable = this.slideUpDrawable) != null) {
            int w = drawable.getIntrinsicWidth();
            int h = this.slideUpDrawable.getIntrinsicHeight();
            int y = (int) (this.centerImage.getDrawRegion().top - AndroidUtilities.dp(((this.currentMoveY / AndroidUtilities.dp(60.0f)) * 6.0f) + 17.0f));
            this.slideUpDrawable.setAlpha((int) ((1.0f - this.currentMoveYProgress) * 255.0f));
            this.slideUpDrawable.setBounds((-w) / 2, (-h) + y, w / 2, y);
            this.slideUpDrawable.draw(canvas);
        }
        if (this.stickerEmojiLayout != null) {
            canvas.translate(-AndroidUtilities.dp(50.0f), ((-this.centerImage.getImageHeight()) / 2) - AndroidUtilities.dp(30.0f));
            this.stickerEmojiLayout.draw(canvas);
        }
        canvas.restore();
        if (this.isVisible) {
            if (this.showProgress != 1.0f) {
                long newTime = System.currentTimeMillis();
                long dt = newTime - this.lastUpdateTime;
                this.lastUpdateTime = newTime;
                this.showProgress += dt / 120.0f;
                this.containerView.invalidate();
                if (this.showProgress > 1.0f) {
                    this.showProgress = 1.0f;
                    return;
                }
                return;
            }
            return;
        }
        if (this.showProgress != 0.0f) {
            long newTime2 = System.currentTimeMillis();
            long dt2 = newTime2 - this.lastUpdateTime;
            this.lastUpdateTime = newTime2;
            this.showProgress -= dt2 / 120.0f;
            this.containerView.invalidate();
            if (this.showProgress < 0.0f) {
                this.showProgress = 0.0f;
            }
            if (this.showProgress == 0.0f) {
                this.centerImage.setImageBitmap((Drawable) null);
                AndroidUtilities.unlockOrientation(this.parentActivity);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ContentPreviewViewer$VpUUeuoQDLC6QhfbnP0JdoHjlhQ
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onDraw$4$ContentPreviewViewer();
                    }
                });
                try {
                    if (this.windowView.getParent() != null) {
                        WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                        wm.removeView(this.windowView);
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
        }
    }

    public /* synthetic */ void lambda$onDraw$4$ContentPreviewViewer() {
        this.centerImage.setImageBitmap((Bitmap) null);
    }
}
