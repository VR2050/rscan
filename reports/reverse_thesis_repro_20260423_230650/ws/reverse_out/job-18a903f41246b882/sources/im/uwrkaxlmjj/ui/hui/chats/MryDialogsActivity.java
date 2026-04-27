package im.uwrkaxlmjj.ui.hui.chats;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Property;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.LinearSmoothScrollerMiddle;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DialogObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.XiaomiUtilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChannelCreateActivity;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.NewContactActivity;
import im.uwrkaxlmjj.ui.ProxyListActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuSubItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BackDrawable;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.MenuDrawable;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter;
import im.uwrkaxlmjj.ui.cells.AccountSelectCell;
import im.uwrkaxlmjj.ui.cells.ArchiveHintInnerCell;
import im.uwrkaxlmjj.ui.cells.DialogCell;
import im.uwrkaxlmjj.ui.cells.DialogsEmptyCell;
import im.uwrkaxlmjj.ui.cells.DividerCell;
import im.uwrkaxlmjj.ui.cells.DrawerActionCell;
import im.uwrkaxlmjj.ui.cells.DrawerAddCell;
import im.uwrkaxlmjj.ui.cells.DrawerProfileCell;
import im.uwrkaxlmjj.ui.cells.DrawerUserCell;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.HashtagSearchCell;
import im.uwrkaxlmjj.ui.cells.HintDialogCell;
import im.uwrkaxlmjj.ui.cells.LoadingCell;
import im.uwrkaxlmjj.ui.cells.ProfileSearchCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AnimatedArrowDrawable;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ChatActivityEnterView;
import im.uwrkaxlmjj.ui.components.CubicBezierInterpolator;
import im.uwrkaxlmjj.ui.components.DialogsItemAnimator;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.FragmentContextView;
import im.uwrkaxlmjj.ui.components.JoinGroupAlert;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.NumberTextView;
import im.uwrkaxlmjj.ui.components.PacmanAnimation;
import im.uwrkaxlmjj.ui.components.ProxyDrawable;
import im.uwrkaxlmjj.ui.components.RLottieDrawable;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.UndoView;
import im.uwrkaxlmjj.ui.constants.ChatEnterMenuType;
import im.uwrkaxlmjj.ui.hui.adapter.MyDialogsAdapter;
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MryDialogsActivity extends BaseSearchViewFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int archive = 105;
    private static final int clear = 103;
    private static final int create_new_channel = 106;
    private static final int create_new_group = 107;
    private static final int delete = 102;
    public static boolean[] dialogsLoaded = new boolean[3];
    private static ArrayList<TLRPC.Dialog> frozenDialogsList = null;
    private static final int mute = 104;
    private static final int pin = 100;
    private static final int read = 101;
    private ArrayList<View> actionModeViews;
    private String addToGroupAlertString;
    private float additionalFloatingTranslation;
    private boolean allowMoving;
    private boolean allowScrollToHiddenView;
    private boolean allowSwipeDuringCurrentTouch;
    private boolean allowSwitchAccount;
    private ActionBarMenuSubItem archiveItem;
    private AnimatedArrowDrawable arrowDrawable;
    private boolean askAboutContacts;
    private BackDrawable backDrawable;
    private int canClearCacheCount;
    private int canMuteCount;
    private int canPinCount;
    private int canReadCount;
    private int canUnmuteCount;
    private boolean cantSendToChannels;
    private boolean checkCanWrite;
    private boolean checkPermission;
    private ActionBarMenuSubItem clearItem;
    private boolean closeSearchFieldOnHide;
    private ChatActivityEnterView commentView;
    private FrameLayout containerLayout;
    private int currentConnectionState;
    private DialogsActivityDelegate delegate;
    private ActionBarMenuItem deleteItem;
    private int dialogChangeFinished;
    private int dialogInsertFinished;
    private int dialogRemoveFinished;
    private MyDialogsAdapter dialogsAdapter;
    private DialogsItemAnimator dialogsItemAnimator;
    private boolean dialogsListFrozen;
    private DialogsSearchAdapter dialogsSearchAdapter;
    private int dialogsType;
    private boolean floatingHidden;
    private final AccelerateDecelerateInterpolator floatingInterpolator;
    private int folderId;
    private ItemTouchHelper itemTouchhelper;
    private int lastItemsCount;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private MenuDrawable menuDrawable;
    private int messagesCount;
    private DialogCell movingView;
    private boolean movingWas;
    private ActionBarMenuItem muteItem;
    private boolean onlySelect;
    private long openedDialogId;
    private PacmanAnimation pacmanAnimation;
    private ActionBarMenuItem passcodeItem;
    private AlertDialog permissionDialog;
    private ActionBarMenuItem pinItem;
    private int prevPosition;
    private int prevTop;
    private RadialProgressView progressView;
    private ProxyDrawable proxyDrawable;
    private ActionBarMenuItem proxyItem;
    private boolean proxyItemVisisble;
    private ActionBarMenuSubItem readItem;
    private boolean resetDelegate;
    private boolean scrollUpdated;
    private boolean scrollingManually;
    private long searchDialogId;
    private EmptyTextProgressView searchEmptyView;
    private TLObject searchObject;
    private String searchString;
    private boolean searchWas;
    private boolean searching;
    private String selectAlertString;
    private String selectAlertStringGroup;
    private NumberTextView selectedDialogsCountTextView;
    private RecyclerView sideMenu;
    private DialogCell slidingView;
    private boolean startedScrollAtTop;
    private SwipeController swipeController;
    private ActionBarMenuItem switchItem;
    private int totalConsumedAmount;
    private UndoView[] undoView;
    private boolean waitingForScrollFinished;

    public interface DialogsActivityDelegate {
        void didSelectDialogs(MryDialogsActivity mryDialogsActivity, ArrayList<Long> arrayList, CharSequence charSequence, boolean z);
    }

    static /* synthetic */ int access$3508(MryDialogsActivity x0) {
        int i = x0.lastItemsCount;
        x0.lastItemsCount = i + 1;
        return i;
    }

    static /* synthetic */ int access$3510(MryDialogsActivity x0) {
        int i = x0.lastItemsCount;
        x0.lastItemsCount = i - 1;
        return i;
    }

    private class ContentView extends SizeNotifierFrameLayout {
        private int inputFieldHeight;

        public ContentView(Context context) {
            super(context);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            setMeasuredDimension(widthSize, heightSize);
            int heightSize2 = heightSize - getPaddingTop();
            measureChildWithMargins(MryDialogsActivity.this.actionBar, widthMeasureSpec, 0, heightMeasureSpec, 0);
            int keyboardSize = getKeyboardHeight();
            int childCount = getChildCount();
            if (MryDialogsActivity.this.commentView != null) {
                measureChildWithMargins(MryDialogsActivity.this.commentView, widthMeasureSpec, 0, heightMeasureSpec, 0);
                Object tag = MryDialogsActivity.this.commentView.getTag();
                if (tag != null && tag.equals(2)) {
                    if (keyboardSize <= AndroidUtilities.dp(20.0f) && !AndroidUtilities.isInMultiwindow) {
                        heightSize2 -= MryDialogsActivity.this.commentView.getEmojiPadding();
                    }
                    this.inputFieldHeight = MryDialogsActivity.this.commentView.getMeasuredHeight();
                } else {
                    this.inputFieldHeight = 0;
                }
            }
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child != null && child.getVisibility() != 8 && child != MryDialogsActivity.this.commentView && child != MryDialogsActivity.this.actionBar) {
                    if (child != MryDialogsActivity.this.listView && child != MryDialogsActivity.this.progressView && child != MryDialogsActivity.this.searchEmptyView) {
                        if (MryDialogsActivity.this.commentView != null && MryDialogsActivity.this.commentView.isPopupView(child)) {
                            if (AndroidUtilities.isInMultiwindow) {
                                if (AndroidUtilities.isTablet()) {
                                    child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.min(AndroidUtilities.dp(320.0f), ((heightSize2 - this.inputFieldHeight) - AndroidUtilities.statusBarHeight) + getPaddingTop()), 1073741824));
                                } else {
                                    child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(((heightSize2 - this.inputFieldHeight) - AndroidUtilities.statusBarHeight) + getPaddingTop(), 1073741824));
                                }
                            } else {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(child.getLayoutParams().height, 1073741824));
                            }
                        } else {
                            measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                        }
                    } else {
                        int contentWidthSpec = View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824);
                        int contentHeightSpec = View.MeasureSpec.makeMeasureSpec(Math.max(AndroidUtilities.dp(10.0f), (heightSize2 - this.inputFieldHeight) + AndroidUtilities.dp(2.0f)), 1073741824);
                        child.measure(contentWidthSpec, contentHeightSpec);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int childLeft;
            int childTop;
            int count = getChildCount();
            Object tag = MryDialogsActivity.this.commentView != null ? MryDialogsActivity.this.commentView.getTag() : null;
            int i = 2;
            int paddingBottom = (tag == null || !tag.equals(2) || getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow) ? 0 : MryDialogsActivity.this.commentView.getEmojiPadding();
            setBottomClip(paddingBottom);
            int i2 = 0;
            while (i2 < count) {
                View child = getChildAt(i2);
                if (child.getVisibility() != 8) {
                    FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) child.getLayoutParams();
                    int width = child.getMeasuredWidth();
                    int height = child.getMeasuredHeight();
                    int gravity = lp.gravity;
                    if (gravity == -1) {
                        gravity = 51;
                    }
                    int absoluteGravity = gravity & 7;
                    int verticalGravity = gravity & 112;
                    int i3 = absoluteGravity & 7;
                    if (i3 == 1) {
                        int childLeft2 = r - l;
                        childLeft = (((childLeft2 - width) / i) + lp.leftMargin) - lp.rightMargin;
                    } else if (i3 == 5) {
                        int childLeft3 = r - width;
                        childLeft = childLeft3 - lp.rightMargin;
                    } else {
                        childLeft = lp.leftMargin;
                    }
                    if (verticalGravity == 16) {
                        int childTop2 = b - paddingBottom;
                        childTop = ((((childTop2 - t) - height) / i) + lp.topMargin) - lp.bottomMargin;
                    } else if (verticalGravity == 48) {
                        int childTop3 = lp.topMargin;
                        childTop = childTop3 + getPaddingTop();
                    } else if (verticalGravity == 80) {
                        int childTop4 = b - paddingBottom;
                        childTop = ((childTop4 - t) - height) - lp.bottomMargin;
                    } else {
                        childTop = lp.topMargin;
                    }
                    if (MryDialogsActivity.this.commentView != null && MryDialogsActivity.this.commentView.isPopupView(child)) {
                        childTop = AndroidUtilities.isInMultiwindow ? (MryDialogsActivity.this.commentView.getTop() - child.getMeasuredHeight()) + AndroidUtilities.dp(1.0f) : MryDialogsActivity.this.commentView.getBottom();
                    }
                    child.layout(childLeft, childTop, width - childLeft, childTop + height);
                }
                i2++;
                i = 2;
            }
            notifyHeightChanged();
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            int action = ev.getActionMasked();
            if (action == 0 || action == 1 || action == 3) {
                if (action == 0) {
                    int currentPosition = MryDialogsActivity.this.layoutManager.findFirstVisibleItemPosition();
                    MryDialogsActivity.this.startedScrollAtTop = currentPosition <= 1;
                } else if (MryDialogsActivity.this.actionBar.isActionModeShowed()) {
                    MryDialogsActivity.this.allowMoving = true;
                }
                MryDialogsActivity.this.totalConsumedAmount = 0;
                MryDialogsActivity.this.allowScrollToHiddenView = false;
            }
            return super.onInterceptTouchEvent(ev);
        }
    }

    class SwipeController extends ItemTouchHelper.Callback {
        private RectF buttonInstance;
        private RecyclerView.ViewHolder currentItemViewHolder;
        private boolean swipeFolderBack;
        private boolean swipingFolder;

        SwipeController() {
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public int getMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            if (MryDialogsActivity.this.waitingForDialogsAnimationEnd() || (MryDialogsActivity.this.parentLayout != null && MryDialogsActivity.this.parentLayout.isInPreviewMode())) {
                return 0;
            }
            if (!this.swipingFolder || !this.swipeFolderBack) {
                if (MryDialogsActivity.this.onlySelect || MryDialogsActivity.this.dialogsType != 0 || MryDialogsActivity.this.slidingView != null || recyclerView.getAdapter() != MryDialogsActivity.this.dialogsAdapter || !(viewHolder.itemView instanceof DialogCell)) {
                    return 0;
                }
                DialogCell dialogCell = (DialogCell) viewHolder.itemView;
                long dialogId = dialogCell.getDialogId();
                if (MryDialogsActivity.this.actionBar.isActionModeShowed()) {
                    TLRPC.Dialog dialog = MryDialogsActivity.this.getMessagesController().dialogs_dict.get(dialogId);
                    if (!MryDialogsActivity.this.allowMoving || dialog == null || !dialog.pinned || DialogObject.isFolderDialogId(dialogId)) {
                        return 0;
                    }
                    MryDialogsActivity.this.movingView = (DialogCell) viewHolder.itemView;
                    MryDialogsActivity.this.movingView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    return makeMovementFlags(3, 0);
                }
                if (!MryDialogsActivity.this.allowSwipeDuringCurrentTouch || dialogId == MryDialogsActivity.this.getUserConfig().clientUserId || dialogId == 777000 || MryDialogsActivity.this.getMessagesController().isProxyDialog(dialogId, false)) {
                    return 0;
                }
                this.swipeFolderBack = false;
                this.swipingFolder = SharedConfig.archiveHidden && DialogObject.isFolderDialogId(dialogCell.getDialogId());
                dialogCell.setSliding(true);
                return makeMovementFlags(0, 4);
            }
            this.swipingFolder = false;
            return 0;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public boolean onMove(RecyclerView recyclerView, RecyclerView.ViewHolder source, RecyclerView.ViewHolder target) {
            if (!(target.itemView instanceof DialogCell)) {
                return false;
            }
            DialogCell dialogCell = (DialogCell) target.itemView;
            long dialogId = dialogCell.getDialogId();
            TLRPC.Dialog dialog = MryDialogsActivity.this.getMessagesController().dialogs_dict.get(dialogId);
            if (dialog == null || !dialog.pinned || DialogObject.isFolderDialogId(dialogId)) {
                return false;
            }
            int fromIndex = source.getAdapterPosition();
            int toIndex = target.getAdapterPosition();
            MryDialogsActivity.this.dialogsAdapter.notifyItemMoved(fromIndex, toIndex);
            MryDialogsActivity.this.updateDialogIndices();
            MryDialogsActivity.this.movingWas = true;
            return true;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public int convertToAbsoluteDirection(int flags, int layoutDirection) {
            if (this.swipeFolderBack) {
                return 0;
            }
            return super.convertToAbsoluteDirection(flags, layoutDirection);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onSwiped(RecyclerView.ViewHolder viewHolder, int direction) {
            if (viewHolder == null) {
                MryDialogsActivity.this.slidingView = null;
                return;
            }
            DialogCell dialogCell = (DialogCell) viewHolder.itemView;
            long dialogId = dialogCell.getDialogId();
            if (!DialogObject.isFolderDialogId(dialogId)) {
                MryDialogsActivity.this.slidingView = dialogCell;
                final int position = viewHolder.getAdapterPosition();
                final int dialogIndex = MryDialogsActivity.this.dialogsAdapter.fixPosition(position);
                final int count = MryDialogsActivity.this.dialogsAdapter.getItemCount();
                Runnable finishRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$SwipeController$twMai3AJ1HDvuQrwBXFfSgKu9NE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onSwiped$1$MryDialogsActivity$SwipeController(dialogIndex, count, position);
                    }
                };
                MryDialogsActivity.this.setDialogsListFrozen(true);
                if (Utilities.random.nextInt(1000) == 1) {
                    if (MryDialogsActivity.this.pacmanAnimation == null) {
                        MryDialogsActivity mryDialogsActivity = MryDialogsActivity.this;
                        mryDialogsActivity.pacmanAnimation = new PacmanAnimation(mryDialogsActivity.listView);
                    }
                    MryDialogsActivity.this.pacmanAnimation.setFinishRunnable(finishRunnable);
                    MryDialogsActivity.this.pacmanAnimation.start();
                    return;
                }
                finishRunnable.run();
                return;
            }
            SharedConfig.toggleArchiveHidden();
            if (SharedConfig.archiveHidden) {
                MryDialogsActivity.this.waitingForScrollFinished = true;
                MryDialogsActivity.this.listView.smoothScrollBy(0, dialogCell.getMeasuredHeight() + dialogCell.getTop(), CubicBezierInterpolator.EASE_OUT);
                MryDialogsActivity.this.getUndoView().showWithAction(0L, 6, null, null);
            }
        }

        public /* synthetic */ void lambda$onSwiped$1$MryDialogsActivity$SwipeController(int dialogIndex, int count, int position) {
            RecyclerView.ViewHolder holder;
            final TLRPC.Dialog dialog = (TLRPC.Dialog) MryDialogsActivity.frozenDialogsList.remove(dialogIndex);
            final int pinnedNum = dialog.pinnedNum;
            MryDialogsActivity.this.slidingView = null;
            MryDialogsActivity.this.listView.invalidate();
            int added = MryDialogsActivity.this.getMessagesController().addDialogToFolder(dialog.id, MryDialogsActivity.this.folderId == 0 ? 1 : 0, -1, 0L);
            if (added == 2) {
                MryDialogsActivity.this.dialogsAdapter.notifyItemChanged(count - 1);
            }
            if (added != 2 || position != 0) {
                MryDialogsActivity.this.dialogsItemAnimator.prepareForRemove();
                MryDialogsActivity.access$3510(MryDialogsActivity.this);
                MryDialogsActivity.this.dialogsAdapter.notifyItemRemoved(position);
                MryDialogsActivity.this.dialogRemoveFinished = 2;
            }
            if (MryDialogsActivity.this.folderId == 0) {
                if (added == 2) {
                    MryDialogsActivity.this.dialogsItemAnimator.prepareForRemove();
                    if (position == 0) {
                        MryDialogsActivity.this.dialogChangeFinished = 2;
                        MryDialogsActivity.this.setDialogsListFrozen(true);
                        MryDialogsActivity.this.dialogsAdapter.notifyItemChanged(0);
                    } else {
                        MryDialogsActivity.access$3508(MryDialogsActivity.this);
                        MryDialogsActivity.this.dialogsAdapter.notifyItemInserted(0);
                        if (!SharedConfig.archiveHidden && MryDialogsActivity.this.layoutManager.findFirstVisibleItemPosition() == 0) {
                            MryDialogsActivity.this.listView.smoothScrollBy(0, -AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 78.0f : 72.0f));
                        }
                    }
                    ArrayList<TLRPC.Dialog> dialogs = MryDialogsActivity.getDialogsArray(MryDialogsActivity.this.currentAccount, MryDialogsActivity.this.dialogsType, MryDialogsActivity.this.folderId, false);
                    MryDialogsActivity.frozenDialogsList.add(0, dialogs.get(0));
                } else if (added == 1 && (holder = MryDialogsActivity.this.listView.findViewHolderForAdapterPosition(0)) != null && (holder.itemView instanceof DialogCell)) {
                    DialogCell cell = (DialogCell) holder.itemView;
                    cell.checkCurrentDialogIndex(true);
                    cell.animateArchiveAvatar();
                }
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                boolean hintShowed = preferences.getBoolean("archivehint_l", false) || SharedConfig.archiveHidden;
                if (!hintShowed) {
                    preferences.edit().putBoolean("archivehint_l", true).commit();
                }
                MryDialogsActivity.this.getUndoView().showWithAction(dialog.id, hintShowed ? 2 : 3, null, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$SwipeController$67jE3Cv0s40fTVzmdgfqIsaLwQ8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$0$MryDialogsActivity$SwipeController(dialog, pinnedNum);
                    }
                });
            }
            if (MryDialogsActivity.this.folderId != 0 && MryDialogsActivity.frozenDialogsList.isEmpty()) {
                MryDialogsActivity.this.listView.setEmptyView(null);
                MryDialogsActivity.this.progressView.setVisibility(4);
            }
        }

        public /* synthetic */ void lambda$null$0$MryDialogsActivity$SwipeController(TLRPC.Dialog dialog, int pinnedNum) {
            MryDialogsActivity.this.dialogsListFrozen = true;
            MryDialogsActivity.this.getMessagesController().addDialogToFolder(dialog.id, 0, pinnedNum, 0L);
            MryDialogsActivity.this.dialogsListFrozen = false;
            ArrayList<TLRPC.Dialog> dialogs = MryDialogsActivity.this.getMessagesController().getDialogs(0);
            int index = dialogs.indexOf(dialog);
            if (index >= 0) {
                ArrayList<TLRPC.Dialog> archivedDialogs = MryDialogsActivity.this.getMessagesController().getDialogs(1);
                if (!archivedDialogs.isEmpty() || index != 1) {
                    MryDialogsActivity.this.dialogInsertFinished = 2;
                    MryDialogsActivity.this.setDialogsListFrozen(true);
                    MryDialogsActivity.this.dialogsItemAnimator.prepareForRemove();
                    MryDialogsActivity.access$3508(MryDialogsActivity.this);
                    MryDialogsActivity.this.dialogsAdapter.notifyItemInserted(index);
                }
                if (archivedDialogs.isEmpty()) {
                    dialogs.remove(0);
                    if (index == 1) {
                        MryDialogsActivity.this.dialogChangeFinished = 2;
                        MryDialogsActivity.this.setDialogsListFrozen(true);
                        MryDialogsActivity.this.dialogsAdapter.notifyItemChanged(0);
                        return;
                    } else {
                        MryDialogsActivity.frozenDialogsList.remove(0);
                        MryDialogsActivity.this.dialogsItemAnimator.prepareForRemove();
                        MryDialogsActivity.access$3510(MryDialogsActivity.this);
                        MryDialogsActivity.this.dialogsAdapter.notifyItemRemoved(0);
                        return;
                    }
                }
                return;
            }
            MryDialogsActivity.this.dialogsAdapter.notifyDataSetChanged();
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onSelectedChanged(RecyclerView.ViewHolder viewHolder, int actionState) {
            if (viewHolder != null) {
                MryDialogsActivity.this.listView.hideSelector();
            }
            super.onSelectedChanged(viewHolder, actionState);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public long getAnimationDuration(RecyclerView recyclerView, int animationType, float animateDx, float animateDy) {
            if (animationType == 4) {
                return 200L;
            }
            if (animationType == 8 && MryDialogsActivity.this.movingView != null) {
                final View view = MryDialogsActivity.this.movingView;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$SwipeController$pKYgjl7AUfMzWP_mLgjq78VlJvI
                    @Override // java.lang.Runnable
                    public final void run() {
                        view.setBackgroundDrawable(null);
                    }
                }, MryDialogsActivity.this.dialogsItemAnimator.getMoveDuration());
                MryDialogsActivity.this.movingView = null;
            }
            return super.getAnimationDuration(recyclerView, animationType, animateDx, animateDy);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public float getSwipeThreshold(RecyclerView.ViewHolder viewHolder) {
            return 0.3f;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public float getSwipeEscapeVelocity(float defaultValue) {
            return 3500.0f;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public float getSwipeVelocityThreshold(float defaultValue) {
            return Float.MAX_VALUE;
        }
    }

    public MryDialogsActivity(Bundle args) {
        super(args);
        this.undoView = new UndoView[2];
        this.actionModeViews = new ArrayList<>();
        this.askAboutContacts = true;
        this.floatingInterpolator = new AccelerateDecelerateInterpolator();
        this.checkPermission = true;
        this.resetDelegate = true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        if (getArguments() != null) {
            this.onlySelect = this.arguments.getBoolean("onlySelect", false);
            this.cantSendToChannels = this.arguments.getBoolean("cantSendToChannels", false);
            this.dialogsType = this.arguments.getInt("dialogsType", 0);
            this.selectAlertString = this.arguments.getString("selectAlertString");
            this.selectAlertStringGroup = this.arguments.getString("selectAlertStringGroup");
            this.addToGroupAlertString = this.arguments.getString("addToGroupAlertString");
            this.allowSwitchAccount = this.arguments.getBoolean("allowSwitchAccount");
            this.checkCanWrite = this.arguments.getBoolean("checkCanWrite", true);
            this.folderId = this.arguments.getInt("folderId", 0);
            this.resetDelegate = this.arguments.getBoolean("resetDelegate", true);
            this.messagesCount = this.arguments.getInt("messagesCount", 0);
        }
        if (this.dialogsType == 0) {
            this.askAboutContacts = MessagesController.getGlobalNotificationsSettings().getBoolean("askAboutContacts", true);
            SharedConfig.loadProxyList();
        }
        if (this.searchString == null) {
            this.currentConnectionState = getConnectionsManager().getConnectionState();
            getNotificationCenter().addObserver(this, NotificationCenter.dialogsNeedReload);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
            if (!this.onlySelect) {
                NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.closeSearchByActiveAction);
                NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.proxySettingsChanged);
            }
            getNotificationCenter().addObserver(this, NotificationCenter.updateInterfaces);
            getNotificationCenter().addObserver(this, NotificationCenter.encryptedChatUpdated);
            getNotificationCenter().addObserver(this, NotificationCenter.contactsDidLoad);
            getNotificationCenter().addObserver(this, NotificationCenter.appDidLogout);
            getNotificationCenter().addObserver(this, NotificationCenter.openedChatChanged);
            getNotificationCenter().addObserver(this, NotificationCenter.notificationsSettingsUpdated);
            getNotificationCenter().addObserver(this, NotificationCenter.messageReceivedByAck);
            getNotificationCenter().addObserver(this, NotificationCenter.messageReceivedByServer);
            getNotificationCenter().addObserver(this, NotificationCenter.messageSendError);
            getNotificationCenter().addObserver(this, NotificationCenter.needReloadRecentDialogsSearch);
            getNotificationCenter().addObserver(this, NotificationCenter.replyMessagesDidLoad);
            getNotificationCenter().addObserver(this, NotificationCenter.reloadHints);
            getNotificationCenter().addObserver(this, NotificationCenter.didUpdateConnectionState);
            getNotificationCenter().addObserver(this, NotificationCenter.dialogsUnreadCounterChanged);
            getNotificationCenter().addObserver(this, NotificationCenter.needDeleteDialog);
            getNotificationCenter().addObserver(this, NotificationCenter.folderBecomeEmpty);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didSetPasscode);
        }
        if (!dialogsLoaded[this.currentAccount]) {
            getMessagesController().loadGlobalNotificationsSettings();
            getMessagesController().loadDialogs(this.folderId, 0, 100, true);
            getMessagesController().loadHintDialogs();
            getContactsController().checkInviteText();
            getMediaDataController().loadRecents(2, false, true, false);
            getMediaDataController().checkFeaturedStickers();
            dialogsLoaded[this.currentAccount] = true;
        }
        getMessagesController().loadPinnedDialogs(this.folderId, 0L, null);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        if (this.searchString == null) {
            getNotificationCenter().removeObserver(this, NotificationCenter.dialogsNeedReload);
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
            if (!this.onlySelect) {
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.closeSearchByActiveAction);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.proxySettingsChanged);
            }
            getNotificationCenter().removeObserver(this, NotificationCenter.updateInterfaces);
            getNotificationCenter().removeObserver(this, NotificationCenter.encryptedChatUpdated);
            getNotificationCenter().removeObserver(this, NotificationCenter.contactsDidLoad);
            getNotificationCenter().removeObserver(this, NotificationCenter.appDidLogout);
            getNotificationCenter().removeObserver(this, NotificationCenter.openedChatChanged);
            getNotificationCenter().removeObserver(this, NotificationCenter.notificationsSettingsUpdated);
            getNotificationCenter().removeObserver(this, NotificationCenter.messageReceivedByAck);
            getNotificationCenter().removeObserver(this, NotificationCenter.messageReceivedByServer);
            getNotificationCenter().removeObserver(this, NotificationCenter.messageSendError);
            getNotificationCenter().removeObserver(this, NotificationCenter.needReloadRecentDialogsSearch);
            getNotificationCenter().removeObserver(this, NotificationCenter.replyMessagesDidLoad);
            getNotificationCenter().removeObserver(this, NotificationCenter.reloadHints);
            getNotificationCenter().removeObserver(this, NotificationCenter.didUpdateConnectionState);
            getNotificationCenter().removeObserver(this, NotificationCenter.dialogsUnreadCounterChanged);
            getNotificationCenter().removeObserver(this, NotificationCenter.needDeleteDialog);
            getNotificationCenter().removeObserver(this, NotificationCenter.folderBecomeEmpty);
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetPasscode);
        }
        ChatActivityEnterView chatActivityEnterView = this.commentView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onDestroy();
        }
        UndoView[] undoViewArr = this.undoView;
        if (undoViewArr[0] != null) {
            undoViewArr[0].hide(true, 0);
        }
        this.delegate = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected MrySearchView getSearchView() {
        FrameLayout searchLayout = new FrameLayout(getParentActivity());
        searchLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.containerLayout.addView(searchLayout, LayoutHelper.createFrame(-1, 55.0f));
        this.searchView = new MrySearchView(getParentActivity());
        this.searchView.setHintText(LocaleController.getString("SearchMessageOrUser", R.string.SearchMessageOrUser));
        searchLayout.addView(this.searchView, LayoutHelper.createFrame(-1, 35, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        return this.searchView;
    }

    protected RecyclerListView getListView() {
        return this.listView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(final Context context) {
        int i;
        String str;
        this.searching = false;
        this.searchWas = false;
        this.pacmanAnimation = null;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$lyRO00nBXjvnL2fasg_7QiRd3dg
            @Override // java.lang.Runnable
            public final void run() {
                Theme.createChatResources(context, false);
            }
        });
        FrameLayout frameLayout = new FrameLayout(context);
        this.containerLayout = frameLayout;
        this.fragmentView = frameLayout;
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        ActionBarMenu menu = this.actionBar.createMenu();
        if (!this.onlySelect && this.searchString == null && this.folderId == 0) {
            ProxyDrawable proxyDrawable = new ProxyDrawable(context);
            this.proxyDrawable = proxyDrawable;
            ActionBarMenuItem actionBarMenuItemAddItem = menu.addItem(2, proxyDrawable);
            this.proxyItem = actionBarMenuItemAddItem;
            actionBarMenuItemAddItem.setContentDescription(LocaleController.getString("ProxySettings", R.string.ProxySettings));
            this.passcodeItem = menu.addItem(1, R.drawable.lock_close);
            updatePasscodeButton();
            updateProxyButton(false);
        }
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitleActionRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$mMVh3VjEBM2jf4q-NGeCCxZZ58o
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createView$1$MryDialogsActivity();
            }
        });
        if (this.allowSwitchAccount && UserConfig.getActivatedAccountsCount() > 1) {
            this.switchItem = menu.addItemWithWidth(1, 0, AndroidUtilities.dp(56.0f));
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            avatarDrawable.setTextSize(AndroidUtilities.dp(12.0f));
            BackupImageView imageView = new BackupImageView(context);
            imageView.setRoundRadius(AndroidUtilities.dp(18.0f));
            this.switchItem.addView(imageView, LayoutHelper.createFrame(36, 36, 17));
            TLRPC.User user = getUserConfig().getCurrentUser();
            avatarDrawable.setInfo(user);
            imageView.getImageReceiver().setCurrentAccount(this.currentAccount);
            imageView.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
            int a = 0;
            for (int i2 = 3; a < i2; i2 = 3) {
                TLRPC.User u = AccountInstance.getInstance(a).getUserConfig().getCurrentUser();
                if (u != null) {
                    AccountSelectCell cell = new AccountSelectCell(context);
                    cell.setAccount(a, true);
                    this.switchItem.addSubItem(a + 10, cell, AndroidUtilities.dp(230.0f), AndroidUtilities.dp(48.0f));
                }
                a++;
            }
        }
        this.actionBar.setAllowOverlayTitle(true);
        ActionBar actionBar = this.actionBar;
        if (this.dialogsType == 5) {
            i = R.string.MyChannels;
            str = "MyChannels";
        } else {
            i = R.string.MyGroups;
            str = "MyGroups";
        }
        actionBar.setTitle(LocaleController.getString(str, i));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (MryDialogsActivity.this.actionBar.isActionModeShowed()) {
                        MryDialogsActivity.this.hideActionMode(true);
                        return;
                    } else {
                        MryDialogsActivity.this.finishFragment();
                        return;
                    }
                }
                if (id == 1) {
                    SharedConfig.appLocked = true ^ SharedConfig.appLocked;
                    SharedConfig.saveConfig();
                    MryDialogsActivity.this.updatePasscodeButton();
                    return;
                }
                if (id == 2) {
                    MryDialogsActivity.this.presentFragment(new ProxyListActivity());
                    return;
                }
                if (id >= 10 && id < 13) {
                    if (MryDialogsActivity.this.getParentActivity() != null) {
                        DialogsActivityDelegate oldDelegate = MryDialogsActivity.this.delegate;
                        LaunchActivity launchActivity = (LaunchActivity) MryDialogsActivity.this.getParentActivity();
                        launchActivity.switchToAccount(id - 10, true);
                        MryDialogsActivity dialogsActivity = new MryDialogsActivity(MryDialogsActivity.this.arguments);
                        dialogsActivity.setDelegate(oldDelegate);
                        launchActivity.presentFragment(dialogsActivity, false, true);
                        return;
                    }
                    return;
                }
                if (id == 100 || id == 101 || id == 102 || id == 103 || id == 104 || id == 105) {
                    MryDialogsActivity.this.perfromSelectedDialogsAction(id, true);
                    return;
                }
                if (id == 106) {
                    Bundle args = new Bundle();
                    args.putInt("step", 0);
                    MryDialogsActivity.this.presentFragment(new ChannelCreateActivity(args), true);
                } else if (id == 107) {
                    MryDialogsActivity.this.presentFragment(new CreateGroupActivity(new Bundle()));
                }
            }
        });
        RecyclerView recyclerView = this.sideMenu;
        if (recyclerView != null) {
            recyclerView.setBackgroundColor(Theme.getColor(Theme.key_chats_menuBackground));
            this.sideMenu.setGlowColor(Theme.getColor(Theme.key_chats_menuBackground));
            this.sideMenu.getAdapter().notifyDataSetChanged();
        }
        ActionBarMenu actionMode = this.actionBar.createActionMode();
        NumberTextView numberTextView = new NumberTextView(actionMode.getContext());
        this.selectedDialogsCountTextView = numberTextView;
        numberTextView.setTextSize(18);
        this.selectedDialogsCountTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.selectedDialogsCountTextView.setTextColor(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon));
        actionMode.addView(this.selectedDialogsCountTextView, LayoutHelper.createLinear(0, -1, 1.0f, 72, 0, 0, 0));
        this.selectedDialogsCountTextView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$YHChKW14ds5qdJvKEvLFz0EzcQM
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return MryDialogsActivity.lambda$createView$2(view, motionEvent);
            }
        });
        this.pinItem = actionMode.addItemWithWidth(100, R.drawable.msg_pin, AndroidUtilities.dp(54.0f));
        this.muteItem = actionMode.addItemWithWidth(104, R.drawable.msg_archive, AndroidUtilities.dp(54.0f));
        this.deleteItem = actionMode.addItemWithWidth(102, R.drawable.msg_delete, AndroidUtilities.dp(54.0f), LocaleController.getString("Delete", R.string.Delete));
        ActionBarMenuItem otherItem = actionMode.addItemWithWidth(0, R.drawable.ic_ab_other, AndroidUtilities.dp(54.0f), LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
        this.readItem = otherItem.addSubItem(101, R.drawable.msg_markread, LocaleController.getString("MarkAsRead", R.string.MarkAsRead));
        this.clearItem = otherItem.addSubItem(103, R.drawable.msg_clear, LocaleController.getString("ClearHistory", R.string.ClearHistory));
        this.actionModeViews.add(this.pinItem);
        this.actionModeViews.add(this.muteItem);
        this.actionModeViews.add(this.deleteItem);
        this.actionModeViews.add(otherItem);
        super.createView(context);
        ContentView contentView = new ContentView(context);
        this.containerLayout.addView(contentView, LayoutHelper.createFrame(-1, -2, 0, AndroidUtilities.dp(55.0f), 0, 0));
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.2
            private boolean firstLayout = true;
            private boolean ignoreLayout;

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, android.view.ViewGroup, android.view.View
            protected void dispatchDraw(Canvas canvas) {
                super.dispatchDraw(canvas);
                if (MryDialogsActivity.this.slidingView != null && MryDialogsActivity.this.pacmanAnimation != null) {
                    MryDialogsActivity.this.pacmanAnimation.draw(canvas, MryDialogsActivity.this.slidingView.getTop() + (MryDialogsActivity.this.slidingView.getMeasuredHeight() / 2));
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView
            public void setAdapter(RecyclerView.Adapter adapter) {
                super.setAdapter(adapter);
                this.firstLayout = true;
            }

            private void checkIfAdapterValid() {
                if (MryDialogsActivity.this.listView != null && MryDialogsActivity.this.dialogsAdapter != null && MryDialogsActivity.this.listView.getAdapter() == MryDialogsActivity.this.dialogsAdapter && MryDialogsActivity.this.lastItemsCount != MryDialogsActivity.this.dialogsAdapter.getItemCount()) {
                    this.ignoreLayout = true;
                    MryDialogsActivity.this.dialogsAdapter.notifyDataSetChanged();
                    this.ignoreLayout = false;
                }
            }

            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (MryDialogsActivity.this.searchEmptyView != null) {
                    MryDialogsActivity.this.searchEmptyView.setPadding(left, top, right, bottom);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.View
            protected void onMeasure(int widthSpec, int heightSpec) {
                if (this.firstLayout && MryDialogsActivity.this.getMessagesController().dialogsLoaded) {
                    if (MryDialogsActivity.this.hasHiddenArchive()) {
                        this.ignoreLayout = true;
                        MryDialogsActivity.this.layoutManager.scrollToPositionWithOffset(1, 0);
                        this.ignoreLayout = false;
                    }
                    this.firstLayout = false;
                }
                checkIfAdapterValid();
                super.onMeasure(widthSpec, heightSpec);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                super.onLayout(changed, l, t, r, b);
                if ((MryDialogsActivity.this.dialogRemoveFinished != 0 || MryDialogsActivity.this.dialogInsertFinished != 0 || MryDialogsActivity.this.dialogChangeFinished != 0) && !MryDialogsActivity.this.dialogsItemAnimator.isRunning()) {
                    MryDialogsActivity.this.onDialogAnimationFinished();
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                if (MryDialogsActivity.this.waitingForScrollFinished || MryDialogsActivity.this.dialogRemoveFinished != 0 || MryDialogsActivity.this.dialogInsertFinished != 0 || MryDialogsActivity.this.dialogChangeFinished != 0) {
                    return false;
                }
                int action = e.getAction();
                if ((action == 1 || action == 3) && !MryDialogsActivity.this.itemTouchhelper.isIdle() && MryDialogsActivity.this.swipeController.swipingFolder) {
                    MryDialogsActivity.this.swipeController.swipeFolderBack = true;
                    if (MryDialogsActivity.this.itemTouchhelper.checkHorizontalSwipe(null, 4) != 0) {
                        SharedConfig.toggleArchiveHidden();
                        MryDialogsActivity.this.getUndoView().showWithAction(0L, 7, null, null);
                    }
                }
                boolean result = super.onTouchEvent(e);
                if ((action == 1 || action == 3) && MryDialogsActivity.this.allowScrollToHiddenView) {
                    int currentPosition = MryDialogsActivity.this.layoutManager.findFirstVisibleItemPosition();
                    if (currentPosition == 0) {
                        View view = MryDialogsActivity.this.layoutManager.findViewByPosition(currentPosition);
                        int height = (AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 78.0f : 72.0f) / 4) * 3;
                        int diff = view.getTop() + view.getMeasuredHeight();
                        if (view != null) {
                            if (diff < height) {
                                MryDialogsActivity.this.listView.smoothScrollBy(0, diff, CubicBezierInterpolator.EASE_OUT_QUINT);
                            } else {
                                MryDialogsActivity.this.listView.smoothScrollBy(0, view.getTop(), CubicBezierInterpolator.EASE_OUT_QUINT);
                            }
                        }
                    }
                    MryDialogsActivity.this.allowScrollToHiddenView = false;
                }
                return result;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent e) {
                if (MryDialogsActivity.this.waitingForScrollFinished || MryDialogsActivity.this.dialogRemoveFinished != 0 || MryDialogsActivity.this.dialogInsertFinished != 0 || MryDialogsActivity.this.dialogChangeFinished != 0) {
                    return false;
                }
                if (e.getAction() == 0) {
                    MryDialogsActivity.this.allowSwipeDuringCurrentTouch = !r0.actionBar.isActionModeShowed();
                    checkIfAdapterValid();
                }
                return super.onInterceptTouchEvent(e);
            }
        };
        this.listView = recyclerListView;
        recyclerListView.addItemDecoration(new TopBottomDecoration(0, 10));
        this.listView.setOverScrollMode(2);
        this.listView.setScrollBarStyle(ConnectionsManager.FileTypeVideo);
        DialogsItemAnimator dialogsItemAnimator = new DialogsItemAnimator() { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.3
            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onRemoveFinished(RecyclerView.ViewHolder item) {
                if (MryDialogsActivity.this.dialogRemoveFinished == 2) {
                    MryDialogsActivity.this.dialogRemoveFinished = 1;
                }
            }

            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onAddFinished(RecyclerView.ViewHolder item) {
                if (MryDialogsActivity.this.dialogInsertFinished == 2) {
                    MryDialogsActivity.this.dialogInsertFinished = 1;
                }
            }

            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onChangeFinished(RecyclerView.ViewHolder item, boolean oldItem) {
                if (MryDialogsActivity.this.dialogChangeFinished == 2) {
                    MryDialogsActivity.this.dialogChangeFinished = 1;
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.DialogsItemAnimator
            protected void onAllAnimationsDone() {
                if (MryDialogsActivity.this.dialogRemoveFinished == 1 || MryDialogsActivity.this.dialogInsertFinished == 1 || MryDialogsActivity.this.dialogChangeFinished == 1) {
                    MryDialogsActivity.this.onDialogAnimationFinished();
                }
            }
        };
        this.dialogsItemAnimator = dialogsItemAnimator;
        this.listView.setItemAnimator(dialogsItemAnimator);
        this.listView.setVerticalScrollBarEnabled(true);
        this.listView.setInstantClick(true);
        this.listView.setTag(4);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.4
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public void smoothScrollToPosition(RecyclerView recyclerView2, RecyclerView.State state, int position) {
                if (MryDialogsActivity.this.hasHiddenArchive() && position == 1) {
                    super.smoothScrollToPosition(recyclerView2, state, position);
                    return;
                }
                LinearSmoothScrollerMiddle linearSmoothScroller = new LinearSmoothScrollerMiddle(recyclerView2.getContext());
                linearSmoothScroller.setTargetPosition(position);
                startSmoothScroll(linearSmoothScroller);
            }

            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public int scrollVerticallyBy(int dy, RecyclerView.Recycler recycler, RecyclerView.State state) {
                View view;
                View view2;
                if (MryDialogsActivity.this.listView.getAdapter() == MryDialogsActivity.this.dialogsAdapter && MryDialogsActivity.this.dialogsType == 0 && !MryDialogsActivity.this.onlySelect && !MryDialogsActivity.this.allowScrollToHiddenView && MryDialogsActivity.this.folderId == 0 && dy < 0 && MryDialogsActivity.this.getMessagesController().hasHiddenArchive()) {
                    int currentPosition = MryDialogsActivity.this.layoutManager.findFirstVisibleItemPosition();
                    if (currentPosition == 0 && (view2 = MryDialogsActivity.this.layoutManager.findViewByPosition(currentPosition)) != null && view2.getBottom() <= AndroidUtilities.dp(1.0f)) {
                        currentPosition = 1;
                    }
                    if (currentPosition != 0 && currentPosition != -1 && (view = MryDialogsActivity.this.layoutManager.findViewByPosition(currentPosition)) != null) {
                        int dialogHeight = AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 78.0f : 72.0f) + 1;
                        int canScrollDy = (-view.getTop()) + ((currentPosition - 1) * dialogHeight);
                        int positiveDy = Math.abs(dy);
                        if (canScrollDy < positiveDy) {
                            MryDialogsActivity.this.totalConsumedAmount += Math.abs(dy);
                            dy = -canScrollDy;
                            if (MryDialogsActivity.this.startedScrollAtTop && MryDialogsActivity.this.totalConsumedAmount >= AndroidUtilities.dp(150.0f)) {
                                MryDialogsActivity.this.allowScrollToHiddenView = true;
                                try {
                                    MryDialogsActivity.this.listView.performHapticFeedback(3, 2);
                                } catch (Exception e) {
                                }
                            }
                        }
                    }
                }
                return super.scrollVerticallyBy(dy, recycler, state);
            }
        };
        this.layoutManager = linearLayoutManager;
        linearLayoutManager.setOrientation(1);
        this.listView.setLayoutManager(this.layoutManager);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        this.listView.setVerticalScrollBarEnabled(false);
        contentView.addView(this.listView, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$n_DKZYFBwfyCjBCmiCbVXUmKD-A
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i3) {
                this.f$0.lambda$createView$3$MryDialogsActivity(view, i3);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.5
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public boolean onItemClick(View view, int position, float x, float y) {
                TLRPC.Chat chat;
                if (MryDialogsActivity.this.getParentActivity() == null) {
                    return false;
                }
                if (!MryDialogsActivity.this.actionBar.isActionModeShowed() && !AndroidUtilities.isTablet() && !MryDialogsActivity.this.onlySelect && (view instanceof DialogCell)) {
                    DialogCell cell2 = (DialogCell) view;
                    if (cell2.isPointInsideAvatar(x, y)) {
                        long dialog_id = cell2.getDialogId();
                        Bundle args = new Bundle();
                        int lower_part = (int) dialog_id;
                        int message_id = cell2.getMessageId();
                        if (lower_part == 0) {
                            return false;
                        }
                        if (lower_part > 0) {
                            args.putInt("user_id", lower_part);
                        } else if (lower_part < 0) {
                            if (message_id != 0 && (chat = MryDialogsActivity.this.getMessagesController().getChat(Integer.valueOf(-lower_part))) != null && chat.migrated_to != null) {
                                args.putInt("migrated_to", lower_part);
                                lower_part = -chat.migrated_to.channel_id;
                            }
                            args.putInt("chat_id", -lower_part);
                        }
                        if (message_id != 0) {
                            args.putInt("message_id", message_id);
                        }
                        if (MryDialogsActivity.this.searchString != null) {
                            if (MryDialogsActivity.this.getMessagesController().checkCanOpenChat(args, MryDialogsActivity.this)) {
                                MryDialogsActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                                MryDialogsActivity.this.presentFragmentAsPreview(new ChatActivity(args));
                            }
                        } else if (MryDialogsActivity.this.getMessagesController().checkCanOpenChat(args, MryDialogsActivity.this)) {
                            MryDialogsActivity.this.presentFragmentAsPreview(new ChatActivity(args));
                        }
                        return true;
                    }
                }
                RecyclerView.Adapter adapter = MryDialogsActivity.this.listView.getAdapter();
                if (adapter == MryDialogsActivity.this.dialogsSearchAdapter) {
                    MryDialogsActivity.this.dialogsSearchAdapter.getItem(position);
                    return false;
                }
                ArrayList<TLRPC.Dialog> dialogs = MryDialogsActivity.getDialogsArray(MryDialogsActivity.this.currentAccount, MryDialogsActivity.this.dialogsType, MryDialogsActivity.this.folderId, MryDialogsActivity.this.dialogsListFrozen);
                int position2 = MryDialogsActivity.this.dialogsAdapter.fixPosition(position);
                if (position2 < 0 || position2 >= dialogs.size()) {
                    return false;
                }
                TLRPC.Dialog dialog = dialogs.get(position2);
                if (MryDialogsActivity.this.onlySelect) {
                    if (MryDialogsActivity.this.dialogsType != 3 || MryDialogsActivity.this.selectAlertString != null || !MryDialogsActivity.this.validateSlowModeDialog(dialog.id)) {
                        return false;
                    }
                    MryDialogsActivity.this.dialogsAdapter.addOrRemoveSelectedDialog(dialog.id, view);
                    MryDialogsActivity.this.updateSelectedCount();
                } else {
                    if (dialog instanceof TLRPC.TL_dialogFolder) {
                        return false;
                    }
                    if (MryDialogsActivity.this.actionBar.isActionModeShowed() && dialog.pinned) {
                        return false;
                    }
                    MryDialogsActivity.this.showOrUpdateActionMode(dialog, view);
                }
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public void onLongClickRelease() {
                MryDialogsActivity.this.finishPreviewFragment();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public void onMove(float dx, float dy) {
                MryDialogsActivity.this.movePreviewFragment(dy);
            }
        });
        SwipeController swipeController = new SwipeController();
        this.swipeController = swipeController;
        ItemTouchHelper itemTouchHelper = new ItemTouchHelper(swipeController);
        this.itemTouchhelper = itemTouchHelper;
        itemTouchHelper.attachToRecyclerView(this.listView);
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.searchEmptyView = emptyTextProgressView;
        emptyTextProgressView.setVisibility(8);
        this.searchEmptyView.setShowAtCenter(true);
        this.searchEmptyView.setTopImage(R.drawable.settings_noresults);
        this.searchEmptyView.setText(LocaleController.getString("SettingsNoResults", R.string.SettingsNoResults));
        contentView.addView(this.searchEmptyView, LayoutHelper.createFrame(-1, -1.0f));
        RadialProgressView radialProgressView = new RadialProgressView(context);
        this.progressView = radialProgressView;
        radialProgressView.setVisibility(8);
        contentView.addView(this.progressView, LayoutHelper.createFrame(-2, -2, 17));
        this.listView.setOnScrollListener(new AnonymousClass6());
        if (this.searchString == null) {
            this.dialogsAdapter = new MyDialogsAdapter(context, this.dialogsType, this.folderId, this.onlySelect) { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.7
                @Override // im.uwrkaxlmjj.ui.hui.adapter.MyDialogsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
                public void notifyDataSetChanged() {
                    MryDialogsActivity.this.lastItemsCount = getItemCount();
                    super.notifyDataSetChanged();
                }
            };
            if (AndroidUtilities.isTablet()) {
                long j = this.openedDialogId;
                if (j != 0) {
                    this.dialogsAdapter.setOpenedDialogId(j);
                }
            }
            this.listView.setAdapter(this.dialogsAdapter);
        }
        int type = 0;
        if (this.searchString != null) {
            type = 2;
        } else if (!this.onlySelect) {
            type = 1;
        }
        DialogsSearchAdapter dialogsSearchAdapter = new DialogsSearchAdapter(context, type, this.dialogsType);
        this.dialogsSearchAdapter = dialogsSearchAdapter;
        dialogsSearchAdapter.setDelegate(new AnonymousClass8());
        this.listView.setEmptyView(this.folderId == 0 ? this.progressView : null);
        if (this.searchString != null) {
            this.actionBar.openSearchField(this.searchString, false);
        }
        if (!this.onlySelect && this.dialogsType == 0) {
            FragmentContextView fragmentLocationContextView = new FragmentContextView(context, this, true);
            contentView.addView(fragmentLocationContextView, LayoutHelper.createFrame(-1.0f, 39.0f, 51, 0.0f, -36.0f, 0.0f, 0.0f));
            FragmentContextView fragmentContextView = new FragmentContextView(context, this, false);
            contentView.addView(fragmentContextView, LayoutHelper.createFrame(-1.0f, 39.0f, 51, 0.0f, -36.0f, 0.0f, 0.0f));
            fragmentContextView.setAdditionalContextView(fragmentLocationContextView);
            fragmentLocationContextView.setAdditionalContextView(fragmentContextView);
        } else if (this.dialogsType == 3 && this.selectAlertString == null) {
            ChatActivityEnterView chatActivityEnterView = this.commentView;
            if (chatActivityEnterView != null) {
                chatActivityEnterView.onDestroy();
            }
            ChatActivityEnterView chatActivityEnterView2 = new ChatActivityEnterView(getParentActivity(), contentView, null, false);
            this.commentView = chatActivityEnterView2;
            chatActivityEnterView2.setAllowStickersAndGifs(false, false);
            this.commentView.setForceShowSendButton(true, false);
            this.commentView.setVisibility(8);
            contentView.addView(this.commentView, LayoutHelper.createFrame(-1, -2, 83));
            this.commentView.setDelegate(new ChatActivityEnterView.ChatActivityEnterViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.9
                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public /* synthetic */ boolean hasScheduledMessages() {
                    return ChatActivityEnterView.ChatActivityEnterViewDelegate.CC.$default$hasScheduledMessages(this);
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public /* synthetic */ void openScheduledMessages() {
                    ChatActivityEnterView.ChatActivityEnterViewDelegate.CC.$default$openScheduledMessages(this);
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public /* synthetic */ void scrollToSendingMessage() {
                    ChatActivityEnterView.ChatActivityEnterViewDelegate.CC.$default$scrollToSendingMessage(this);
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onMessageSend(CharSequence message, boolean notify, int scheduleDate) {
                    if (MryDialogsActivity.this.delegate != null) {
                        ArrayList<Long> selectedDialogs = MryDialogsActivity.this.dialogsAdapter.getSelectedDialogs();
                        if (!selectedDialogs.isEmpty()) {
                            MryDialogsActivity.this.delegate.didSelectDialogs(MryDialogsActivity.this, selectedDialogs, message, false);
                        }
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onSwitchRecordMode(boolean video) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onTextSelectionChanged(int start, int end) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onStickersExpandedChange() {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onPreAudioVideoRecord() {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onTextChanged(CharSequence text, boolean bigChange) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onTextSpansChanged(CharSequence text) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void needSendTyping() {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onAttachButtonHidden() {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onAttachButtonShow() {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onMessageEditEnd(boolean loading) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onWindowSizeChanged(int size) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onStickersTab(boolean opened) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void didPressedAttachButton(int position, ChatEnterMenuType menuType) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void needStartRecordVideo(int state, boolean notify, int scheduleDate) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void needChangeVideoPreviewState(int state, float seekProgress) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void needStartRecordAudio(int state) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void needShowMediaBanHint() {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
                public void onUpdateSlowModeButton(View button, boolean show, CharSequence time) {
                }
            });
        }
        for (int a2 = 0; a2 < 2; a2++) {
            this.undoView[a2] = new UndoView(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.10
                @Override // android.view.View
                public void setTranslationY(float translationY) {
                    super.setTranslationY(translationY);
                    if (this == MryDialogsActivity.this.undoView[0] && MryDialogsActivity.this.undoView[1].getVisibility() != 0) {
                        float diff = (getMeasuredHeight() + AndroidUtilities.dp(8.0f)) - translationY;
                        MryDialogsActivity.this.additionalFloatingTranslation = diff;
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.UndoView
                protected boolean canUndo() {
                    return !MryDialogsActivity.this.dialogsItemAnimator.isRunning();
                }
            };
            contentView.addView(this.undoView[a2], LayoutHelper.createFrame(-1.0f, -2.0f, 83, 8.0f, 0.0f, 8.0f, 8.0f));
        }
        int a3 = this.folderId;
        if (a3 != 0) {
            this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultArchived));
            this.listView.setGlowColor(Theme.getColor(Theme.key_actionBarDefaultArchived));
            this.actionBar.setTitleColor(Theme.getColor(Theme.key_actionBarDefaultArchivedTitle));
            this.actionBar.setItemsColor(Theme.getColor(Theme.key_actionBarDefaultArchivedIcon), false);
            this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultArchivedSelector), false);
            this.actionBar.setSearchTextColor(Theme.getColor(Theme.key_actionBarDefaultArchivedSearch), false);
            this.actionBar.setSearchTextColor(Theme.getColor(Theme.key_actionBarDefaultArchivedSearchPlaceholder), true);
        }
        return this.fragmentView;
    }

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
    public /* synthetic */ void lambda$createView$1$MryDialogsActivity() {
        this.listView.smoothScrollToPosition(hasHiddenArchive() ? 1 : 0);
    }

    static /* synthetic */ boolean lambda$createView$2(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$3$MryDialogsActivity(View view, int position) {
        long dialog_id;
        TLRPC.Chat chat;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView == null || recyclerListView.getAdapter() == null || getParentActivity() == null) {
            return;
        }
        int message_id = 0;
        boolean isGlobalSearch = false;
        RecyclerView.Adapter adapter = this.listView.getAdapter();
        MyDialogsAdapter myDialogsAdapter = this.dialogsAdapter;
        if (adapter != myDialogsAdapter) {
            DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
            if (adapter != dialogsSearchAdapter) {
                dialog_id = 0;
            } else {
                Object obj = dialogsSearchAdapter.getItem(position);
                isGlobalSearch = this.dialogsSearchAdapter.isGlobalSearch(position);
                if (obj instanceof TLRPC.User) {
                    dialog_id = ((TLRPC.User) obj).id;
                    if (!this.onlySelect) {
                        this.searchDialogId = dialog_id;
                        this.searchObject = (TLRPC.User) obj;
                    }
                } else if (obj instanceof TLRPC.Chat) {
                    dialog_id = -((TLRPC.Chat) obj).id;
                    if (!this.onlySelect) {
                        this.searchDialogId = dialog_id;
                        this.searchObject = (TLRPC.Chat) obj;
                    }
                } else if (obj instanceof TLRPC.EncryptedChat) {
                    dialog_id = ((long) ((TLRPC.EncryptedChat) obj).id) << 32;
                    if (!this.onlySelect) {
                        this.searchDialogId = dialog_id;
                        this.searchObject = (TLRPC.EncryptedChat) obj;
                    }
                } else if (obj instanceof MessageObject) {
                    MessageObject messageObject = (MessageObject) obj;
                    dialog_id = messageObject.getDialogId();
                    message_id = messageObject.getId();
                    DialogsSearchAdapter dialogsSearchAdapter2 = this.dialogsSearchAdapter;
                    dialogsSearchAdapter2.addHashtagsFromMessage(dialogsSearchAdapter2.getLastSearchString());
                } else {
                    if (obj instanceof String) {
                        String str = (String) obj;
                        if (this.dialogsSearchAdapter.isHashtagSearch()) {
                            this.actionBar.openSearchField(str, false);
                        } else if (!str.equals("section")) {
                            NewContactActivity activity = new NewContactActivity();
                            activity.setInitialPhoneNumber(str);
                            presentFragment(activity);
                        }
                    }
                    dialog_id = 0;
                }
            }
        } else {
            TLObject object = myDialogsAdapter.getItem(position);
            if (object instanceof TLRPC.User) {
                dialog_id = ((TLRPC.User) object).id;
            } else if (object instanceof TLRPC.Dialog) {
                TLRPC.Dialog dialog = (TLRPC.Dialog) object;
                if (dialog instanceof TLRPC.TL_dialogFolder) {
                    if (this.actionBar.isActionModeShowed()) {
                        return;
                    }
                    TLRPC.TL_dialogFolder dialogFolder = (TLRPC.TL_dialogFolder) dialog;
                    Bundle args = new Bundle();
                    args.putInt("folderId", dialogFolder.folder.id);
                    presentFragment(new MryDialogsActivity(args));
                    return;
                }
                long dialog_id2 = dialog.id;
                if (this.actionBar.isActionModeShowed()) {
                    showOrUpdateActionMode(dialog, view);
                    return;
                }
                dialog_id = dialog_id2;
            } else if (object instanceof TLRPC.TL_recentMeUrlChat) {
                dialog_id = -((TLRPC.TL_recentMeUrlChat) object).chat_id;
            } else if (object instanceof TLRPC.TL_recentMeUrlUser) {
                dialog_id = ((TLRPC.TL_recentMeUrlUser) object).user_id;
            } else if (object instanceof TLRPC.TL_recentMeUrlChatInvite) {
                TLRPC.TL_recentMeUrlChatInvite chatInvite = (TLRPC.TL_recentMeUrlChatInvite) object;
                TLRPC.ChatInvite invite = chatInvite.chat_invite;
                if ((invite.chat == null && (!invite.channel || invite.megagroup)) || (invite.chat != null && (!ChatObject.isChannel(invite.chat) || invite.chat.megagroup))) {
                    String hash = chatInvite.url;
                    int index = hash.indexOf(47);
                    if (index > 0) {
                        hash = hash.substring(index + 1);
                    }
                    showDialog(new JoinGroupAlert(getParentActivity(), invite, hash, this));
                    return;
                }
                if (invite.chat != null) {
                    long dialog_id3 = -invite.chat.id;
                    dialog_id = dialog_id3;
                } else {
                    return;
                }
            } else {
                if (!(object instanceof TLRPC.TL_recentMeUrlStickerSet)) {
                    if (object instanceof TLRPC.TL_recentMeUrlUnknown) {
                        return;
                    } else {
                        return;
                    }
                }
                TLRPC.StickerSet stickerSet = ((TLRPC.TL_recentMeUrlStickerSet) object).set.set;
                TLRPC.TL_inputStickerSetID set = new TLRPC.TL_inputStickerSetID();
                set.id = stickerSet.id;
                set.access_hash = stickerSet.access_hash;
                showDialog(new StickersAlert(getParentActivity(), this, set, null, null));
                return;
            }
        }
        if (dialog_id == 0) {
            return;
        }
        if (this.onlySelect) {
            if (!validateSlowModeDialog(dialog_id)) {
                return;
            }
            if (!this.dialogsAdapter.hasSelectedDialogs()) {
                didSelectResult(dialog_id, true, false);
                return;
            } else {
                this.dialogsAdapter.addOrRemoveSelectedDialog(dialog_id, view);
                updateSelectedCount();
                return;
            }
        }
        Bundle args2 = new Bundle();
        int lower_part = (int) dialog_id;
        int high_id = (int) (dialog_id >> 32);
        if (lower_part != 0) {
            if (lower_part > 0) {
                args2.putInt("user_id", lower_part);
            } else if (lower_part < 0) {
                if (message_id != 0 && (chat = getMessagesController().getChat(Integer.valueOf(-lower_part))) != null && chat.migrated_to != null) {
                    args2.putInt("migrated_to", lower_part);
                    lower_part = -chat.migrated_to.channel_id;
                }
                args2.putInt("chat_id", -lower_part);
            }
        } else {
            args2.putInt("enc_id", high_id);
        }
        if (message_id != 0) {
            args2.putInt("message_id", message_id);
        } else if (!isGlobalSearch) {
            closeSearch();
        } else {
            TLObject tLObject = this.searchObject;
            if (tLObject != null) {
                this.dialogsSearchAdapter.putRecentSearch(this.searchDialogId, tLObject);
                this.searchObject = null;
            }
        }
        if (AndroidUtilities.isTablet()) {
            if (this.openedDialogId == dialog_id && adapter != this.dialogsSearchAdapter) {
                return;
            }
            MyDialogsAdapter myDialogsAdapter2 = this.dialogsAdapter;
            if (myDialogsAdapter2 != null) {
                this.openedDialogId = dialog_id;
                myDialogsAdapter2.setOpenedDialogId(dialog_id);
                updateVisibleRows(512);
            }
        }
        if (this.searchString != null) {
            if (getMessagesController().checkCanOpenChat(args2, this)) {
                getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                presentFragment(new ChatActivity(args2));
                return;
            }
            return;
        }
        if (getMessagesController().checkCanOpenChat(args2, this)) {
            presentFragment(new ChatActivity(args2));
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity$6, reason: invalid class name */
    class AnonymousClass6 extends RecyclerView.OnScrollListener {
        AnonymousClass6() {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
            if (newState == 1) {
                if (MryDialogsActivity.this.searching && MryDialogsActivity.this.searchWas) {
                    AndroidUtilities.hideKeyboard(MryDialogsActivity.this.getParentActivity().getCurrentFocus());
                }
                MryDialogsActivity.this.scrollingManually = true;
            } else {
                MryDialogsActivity.this.scrollingManually = false;
            }
            if (MryDialogsActivity.this.waitingForScrollFinished && newState == 0) {
                MryDialogsActivity.this.waitingForScrollFinished = false;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            int firstVisibleItem = MryDialogsActivity.this.layoutManager.findFirstVisibleItemPosition();
            int visibleItemCount = Math.abs(MryDialogsActivity.this.layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
            int totalItemCount = recyclerView.getAdapter().getItemCount();
            MryDialogsActivity.this.dialogsItemAnimator.onListScroll(-dy);
            if (MryDialogsActivity.this.searching && MryDialogsActivity.this.searchWas) {
                if (visibleItemCount > 0 && MryDialogsActivity.this.layoutManager.findLastVisibleItemPosition() == totalItemCount - 1 && !MryDialogsActivity.this.dialogsSearchAdapter.isMessagesSearchEndReached()) {
                    MryDialogsActivity.this.dialogsSearchAdapter.loadMoreSearchMessages();
                    return;
                }
                return;
            }
            if (visibleItemCount > 0 && MryDialogsActivity.this.layoutManager.findLastVisibleItemPosition() >= MryDialogsActivity.getDialogsArray(MryDialogsActivity.this.currentAccount, MryDialogsActivity.this.dialogsType, MryDialogsActivity.this.folderId, MryDialogsActivity.this.dialogsListFrozen).size() - 10) {
                final boolean fromCache = !MryDialogsActivity.this.getMessagesController().isDialogsEndReached(MryDialogsActivity.this.folderId);
                if (fromCache || !MryDialogsActivity.this.getMessagesController().isServerDialogsEndReached(MryDialogsActivity.this.folderId)) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$6$cL87iGyHG6isIoY3Q57tvad9GfU
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onScrolled$0$MryDialogsActivity$6(fromCache);
                        }
                    });
                }
            }
        }

        public /* synthetic */ void lambda$onScrolled$0$MryDialogsActivity$6(boolean fromCache) {
            MryDialogsActivity.this.getMessagesController().loadDialogs(MryDialogsActivity.this.folderId, -1, 100, fromCache);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity$8, reason: invalid class name */
    class AnonymousClass8 implements DialogsSearchAdapter.DialogsSearchAdapterDelegate {
        AnonymousClass8() {
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void searchStateChanged(boolean search) {
            if (MryDialogsActivity.this.searching && MryDialogsActivity.this.searchWas && MryDialogsActivity.this.searchEmptyView != null) {
                if (search) {
                    MryDialogsActivity.this.searchEmptyView.showProgress();
                } else {
                    MryDialogsActivity.this.searchEmptyView.showTextView();
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void didPressedOnSubDialog(long did) {
            if (MryDialogsActivity.this.onlySelect) {
                if (MryDialogsActivity.this.validateSlowModeDialog(did)) {
                    if (MryDialogsActivity.this.dialogsAdapter.hasSelectedDialogs()) {
                        MryDialogsActivity.this.dialogsAdapter.addOrRemoveSelectedDialog(did, null);
                        MryDialogsActivity.this.updateSelectedCount();
                        MryDialogsActivity.this.closeSearch();
                        return;
                    }
                    MryDialogsActivity.this.didSelectResult(did, true, false);
                    return;
                }
                return;
            }
            int lower_id = (int) did;
            Bundle args = new Bundle();
            if (lower_id > 0) {
                args.putInt("user_id", lower_id);
            } else {
                args.putInt("chat_id", -lower_id);
            }
            MryDialogsActivity.this.closeSearch();
            if (AndroidUtilities.isTablet() && MryDialogsActivity.this.dialogsAdapter != null) {
                MryDialogsActivity.this.dialogsAdapter.setOpenedDialogId(MryDialogsActivity.this.openedDialogId = did);
                MryDialogsActivity.this.updateVisibleRows(512);
            }
            if (MryDialogsActivity.this.searchString != null) {
                if (MryDialogsActivity.this.getMessagesController().checkCanOpenChat(args, MryDialogsActivity.this)) {
                    MryDialogsActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                    MryDialogsActivity.this.presentFragment(new ChatActivity(args));
                    return;
                }
                return;
            }
            if (MryDialogsActivity.this.getMessagesController().checkCanOpenChat(args, MryDialogsActivity.this)) {
                MryDialogsActivity.this.presentFragment(new ChatActivity(args));
            }
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void needRemoveHint(final int did) {
            TLRPC.User user;
            if (MryDialogsActivity.this.getParentActivity() == null || (user = MryDialogsActivity.this.getMessagesController().getUser(Integer.valueOf(did))) == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(MryDialogsActivity.this.getParentActivity());
            builder.setTitle(LocaleController.getString("ChatHintsDeleteAlertTitle", R.string.ChatHintsDeleteAlertTitle));
            builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("ChatHintsDeleteAlert", R.string.ChatHintsDeleteAlert, ContactsController.formatName(user.first_name, user.last_name))));
            builder.setPositiveButton(LocaleController.getString("StickersRemove", R.string.StickersRemove), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$8$EzxIGJje0Yixn3LeuFoCQOlDKvU
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$needRemoveHint$0$MryDialogsActivity$8(did, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            MryDialogsActivity.this.showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }

        public /* synthetic */ void lambda$needRemoveHint$0$MryDialogsActivity$8(int did, DialogInterface dialogInterface, int i) {
            MryDialogsActivity.this.getMediaDataController().removePeer(did);
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void needClearList() {
            AlertDialog.Builder builder = new AlertDialog.Builder(MryDialogsActivity.this.getParentActivity());
            builder.setTitle(LocaleController.getString("ClearSearchAlertTitle", R.string.ClearSearchAlertTitle));
            builder.setMessage(LocaleController.getString("ClearSearchAlert", R.string.ClearSearchAlert));
            builder.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$8$jDuQ98tnb6iVVeOkCEmFItt8t2U
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$needClearList$1$MryDialogsActivity$8(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            MryDialogsActivity.this.showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }

        public /* synthetic */ void lambda$needClearList$1$MryDialogsActivity$8(DialogInterface dialogInterface, int i) {
            if (MryDialogsActivity.this.dialogsSearchAdapter.isRecentSearchDisplayed()) {
                MryDialogsActivity.this.dialogsSearchAdapter.clearRecentSearch();
            } else {
                MryDialogsActivity.this.dialogsSearchAdapter.clearRecentHashtags();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        MyDialogsAdapter myDialogsAdapter = this.dialogsAdapter;
        if (myDialogsAdapter != null && !this.dialogsListFrozen) {
            myDialogsAdapter.notifyDataSetChanged();
        }
        ChatActivityEnterView chatActivityEnterView = this.commentView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onResume();
        }
        if (!this.onlySelect && this.folderId == 0) {
            getMediaDataController().checkStickers(4);
        }
        DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
        if (dialogsSearchAdapter != null) {
            dialogsSearchAdapter.notifyDataSetChanged();
        }
        if (this.checkPermission && !this.onlySelect && Build.VERSION.SDK_INT >= 23) {
            FragmentActivity activity = getParentActivity();
            if (activity != null) {
                this.checkPermission = false;
                boolean hasNotStoragePermission = activity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0;
                if (hasNotStoragePermission) {
                    if (hasNotStoragePermission && activity.shouldShowRequestPermissionRationale("android.permission.WRITE_EXTERNAL_STORAGE")) {
                        AlertDialog.Builder builder = new AlertDialog.Builder(activity);
                        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                        builder.setMessage(LocaleController.getString("PermissionStorage", R.string.PermissionStorage));
                        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                        AlertDialog alertDialogCreate = builder.create();
                        this.permissionDialog = alertDialogCreate;
                        showDialog(alertDialogCreate);
                        return;
                    }
                    askForPermissons(true);
                    return;
                }
                return;
            }
            return;
        }
        if (this.onlySelect || !XiaomiUtilities.isMIUI() || Build.VERSION.SDK_INT < 19 || XiaomiUtilities.isCustomPermissionGranted(XiaomiUtilities.OP_SHOW_WHEN_LOCKED) || getParentActivity() == null || MessagesController.getGlobalNotificationsSettings().getBoolean("askedAboutMiuiLockscreen", false)) {
            return;
        }
        showDialog(new AlertDialog.Builder(getParentActivity()).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("PermissionXiaomiLockscreen", R.string.PermissionXiaomiLockscreen)).setPositiveButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$hbpnpcbIsTbfBWqzBUbeK4Skgtk
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$onResume$4$MryDialogsActivity(dialogInterface, i);
            }
        }).setNegativeButton(LocaleController.getString("ContactsPermissionAlertNotNow", R.string.ContactsPermissionAlertNotNow), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$wZYUl4nVMDgEB50fn6YVm7yGPFQ
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                MessagesController.getGlobalNotificationsSettings().edit().putBoolean("askedAboutMiuiLockscreen", true).commit();
            }
        }).create());
    }

    public /* synthetic */ void lambda$onResume$4$MryDialogsActivity(DialogInterface dialog, int which) {
        Intent intent = XiaomiUtilities.getPermissionManagerIntent();
        if (intent != null) {
            try {
                getParentActivity().startActivity(intent);
            } catch (Exception e) {
                try {
                    Intent intent2 = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
                    intent2.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
                    getParentActivity().startActivity(intent2);
                } catch (Exception xx) {
                    FileLog.e(xx);
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        ChatActivityEnterView chatActivityEnterView = this.commentView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onResume();
        }
        UndoView[] undoViewArr = this.undoView;
        if (undoViewArr[0] != null) {
            undoViewArr[0].hide(true, 0);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (this.actionBar != null && this.actionBar.isActionModeShowed()) {
            hideActionMode(true);
            return false;
        }
        ChatActivityEnterView chatActivityEnterView = this.commentView;
        if (chatActivityEnterView != null && chatActivityEnterView.isPopupShowing()) {
            this.commentView.hidePopup(true);
            return false;
        }
        return super.onBackPressed();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onBecomeFullyHidden() {
        if (this.closeSearchFieldOnHide) {
            if (this.actionBar != null) {
                this.actionBar.closeSearchField();
            }
            TLObject tLObject = this.searchObject;
            if (tLObject != null) {
                this.dialogsSearchAdapter.putRecentSearch(this.searchDialogId, tLObject);
                this.searchObject = null;
            }
            this.closeSearchFieldOnHide = false;
        }
        UndoView[] undoViewArr = this.undoView;
        if (undoViewArr[0] != null) {
            undoViewArr[0].hide(true, 0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean hasHiddenArchive() {
        return this.listView.getAdapter() == this.dialogsAdapter && !this.onlySelect && this.dialogsType == 0 && this.folderId == 0 && getMessagesController().hasHiddenArchive();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean waitingForDialogsAnimationEnd() {
        return (!this.dialogsItemAnimator.isRunning() && this.dialogRemoveFinished == 0 && this.dialogInsertFinished == 0 && this.dialogChangeFinished == 0) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onDialogAnimationFinished() {
        this.dialogRemoveFinished = 0;
        this.dialogInsertFinished = 0;
        this.dialogChangeFinished = 0;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$edWsRLYx8c1tU8QkDRQHVZbpeNg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onDialogAnimationFinished$6$MryDialogsActivity();
            }
        });
    }

    public /* synthetic */ void lambda$onDialogAnimationFinished$6$MryDialogsActivity() {
        if (this.folderId != 0 && frozenDialogsList.isEmpty()) {
            this.listView.setEmptyView(null);
            this.progressView.setVisibility(4);
            finishFragment();
        }
        setDialogsListFrozen(false);
        updateDialogIndices();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideActionMode(boolean animateCheck) {
        this.actionBar.hideActionMode();
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.dialogsAdapter.setEdit(false);
        this.dialogsAdapter.notifyDataSetChanged();
        if (this.menuDrawable != null) {
            this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrOpenMenu", R.string.AccDescrOpenMenu));
        }
        this.dialogsAdapter.getSelectedDialogs().clear();
        MenuDrawable menuDrawable = this.menuDrawable;
        if (menuDrawable != null) {
            menuDrawable.setRotation(0.0f, true);
        } else {
            BackDrawable backDrawable = this.backDrawable;
            if (backDrawable != null) {
                backDrawable.setRotation(0.0f, true);
            }
        }
        this.allowMoving = false;
        if (this.movingWas) {
            getMessagesController().reorderPinnedDialogs(this.folderId, null, 0L);
            this.movingWas = false;
        }
        updateCounters(true);
        this.dialogsAdapter.onReorderStateChanged(false);
        updateVisibleRows(196608 | (animateCheck ? 8192 : 0));
    }

    private int getPinnedCount() {
        int pinnedCount = 0;
        ArrayList<TLRPC.Dialog> dialogs = getMessagesController().getDialogs(this.folderId);
        int N = dialogs.size();
        for (int a = 0; a < N; a++) {
            TLRPC.Dialog dialog = dialogs.get(a);
            if (!(dialog instanceof TLRPC.TL_dialogFolder)) {
                if (!dialog.pinned) {
                    break;
                }
                pinnedCount++;
            }
        }
        return pinnedCount;
    }

    /* JADX INFO: Access modifiers changed from: private */
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
    public void perfromSelectedDialogsAction(final int i, boolean z) {
        TLRPC.User tL_userEmpty;
        TLRPC.Chat chat;
        int i2;
        ArrayList<TLRPC.Dialog> arrayList;
        int i3;
        if (getParentActivity() == null) {
            return;
        }
        ArrayList<Long> selectedDialogs = this.dialogsAdapter.getSelectedDialogs();
        int size = selectedDialogs.size();
        if (i == 105) {
            final ArrayList<Long> arrayList2 = new ArrayList<>(selectedDialogs);
            getMessagesController().addDialogToFolder(arrayList2, this.folderId == 0 ? 1 : 0, -1, null, 0L);
            hideActionMode(false);
            if (this.folderId == 0) {
                SharedPreferences globalMainSettings = MessagesController.getGlobalMainSettings();
                boolean z2 = globalMainSettings.getBoolean("archivehint_l", false) || SharedConfig.archiveHidden;
                if (!z2) {
                    globalMainSettings.edit().putBoolean("archivehint_l", true).commit();
                }
                if (z2) {
                    i3 = arrayList2.size() > 1 ? 4 : 2;
                } else {
                    i3 = arrayList2.size() > 1 ? 5 : 3;
                }
                getUndoView().showWithAction(0L, i3, null, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$x8usxIsKtITiJ8yzcGvYm_W4i9M
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$perfromSelectedDialogsAction$7$MryDialogsActivity(arrayList2);
                    }
                });
                return;
            }
            if (getMessagesController().getDialogs(this.folderId).isEmpty()) {
                this.listView.setEmptyView(null);
                this.progressView.setVisibility(4);
                finishFragment();
                return;
            }
            return;
        }
        if (i == 100 && this.canPinCount != 0) {
            int i4 = 0;
            int i5 = 0;
            int i6 = 0;
            int i7 = 0;
            ArrayList<TLRPC.Dialog> dialogs = getMessagesController().getDialogs(this.folderId);
            int i8 = 0;
            int size2 = dialogs.size();
            while (i8 < size2) {
                TLRPC.Dialog dialog = dialogs.get(i8);
                if (dialog instanceof TLRPC.TL_dialogFolder) {
                    arrayList = dialogs;
                } else {
                    arrayList = dialogs;
                    int i9 = (int) dialog.id;
                    if (!dialog.pinned) {
                        break;
                    } else if (i9 == 0) {
                        i5++;
                    } else {
                        i4++;
                    }
                }
                i8++;
                dialogs = arrayList;
            }
            for (int i10 = 0; i10 < size; i10++) {
                long jLongValue = selectedDialogs.get(i10).longValue();
                TLRPC.Dialog dialog2 = getMessagesController().dialogs_dict.get(jLongValue);
                if (dialog2 != null && !dialog2.pinned) {
                    if (((int) jLongValue) == 0) {
                        i7++;
                    } else {
                        i6++;
                    }
                }
            }
            if (this.folderId != 0) {
                i2 = getMessagesController().maxFolderPinnedDialogsCount;
            } else {
                i2 = getMessagesController().maxPinnedDialogsCount;
            }
            if (i7 + i5 > i2 || i6 + i4 > i2) {
                AlertsCreator.showSimpleAlert(this, LocaleController.formatString("PinToTopLimitReached", R.string.PinToTopLimitReached, LocaleController.formatPluralString("Chats", i2)));
                AndroidUtilities.shakeView(this.pinItem, 2.0f, 0);
                Vibrator vibrator = (Vibrator) getParentActivity().getSystemService("vibrator");
                if (vibrator != null) {
                    vibrator.vibrate(200L);
                    return;
                }
                return;
            }
        } else if ((i == 102 || i == 103) && size > 1 && z && z) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            if (i == 102) {
                builder.setTitle(LocaleController.formatString("DeleteFewChatsTitle", R.string.DeleteFewChatsTitle, LocaleController.formatPluralString("ChatsSelected", size)));
                builder.setMessage(LocaleController.getString("AreYouSureDeleteFewChats", R.string.AreYouSureDeleteFewChats));
                builder.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$xBtrXz_Mnd66i0_ZkdfVJU_YBfk
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i11) {
                        this.f$0.lambda$perfromSelectedDialogsAction$8$MryDialogsActivity(i, dialogInterface, i11);
                    }
                });
            } else if (this.canClearCacheCount != 0) {
                builder.setTitle(LocaleController.formatString("ClearCacheFewChatsTitle", R.string.ClearCacheFewChatsTitle, LocaleController.formatPluralString("ChatsSelectedClearCache", size)));
                builder.setMessage(LocaleController.getString("AreYouSureClearHistoryCacheFewChats", R.string.AreYouSureClearHistoryCacheFewChats));
                builder.setPositiveButton(LocaleController.getString("ClearHistoryCache", R.string.ClearHistoryCache), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$1oY_laN-AOqmw58N1Tsxh24VmNE
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i11) {
                        this.f$0.lambda$perfromSelectedDialogsAction$9$MryDialogsActivity(i, dialogInterface, i11);
                    }
                });
            } else {
                builder.setTitle(LocaleController.formatString("ClearFewChatsTitle", R.string.ClearFewChatsTitle, LocaleController.formatPluralString("ChatsSelectedClear", size)));
                builder.setMessage(LocaleController.getString("AreYouSureClearHistoryFewChats", R.string.AreYouSureClearHistoryFewChats));
                builder.setPositiveButton(LocaleController.getString("ClearHistory", R.string.ClearHistory), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$JH2mNooRqGW8y_gmjtuMDrTaoSk
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i11) {
                        this.f$0.lambda$perfromSelectedDialogsAction$10$MryDialogsActivity(i, dialogInterface, i11);
                    }
                });
            }
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog alertDialogCreate = builder.create();
            showDialog(alertDialogCreate);
            TextView textView = (TextView) alertDialogCreate.getButton(-1);
            if (textView != null) {
                textView.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
                return;
            }
            return;
        }
        boolean z3 = false;
        int i11 = 0;
        while (i11 < size) {
            final long jLongValue2 = selectedDialogs.get(i11).longValue();
            TLRPC.Dialog dialog3 = getMessagesController().dialogs_dict.get(jLongValue2);
            if (dialog3 != null) {
                int i12 = (int) jLongValue2;
                int i13 = (int) (jLongValue2 >> 32);
                if (i12 != 0) {
                    if (i12 <= 0) {
                        tL_userEmpty = null;
                        chat = getMessagesController().getChat(Integer.valueOf(-i12));
                    } else {
                        tL_userEmpty = getMessagesController().getUser(Integer.valueOf(i12));
                        chat = null;
                    }
                } else {
                    TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(i13));
                    if (encryptedChat != null) {
                        tL_userEmpty = getMessagesController().getUser(Integer.valueOf(encryptedChat.user_id));
                        chat = null;
                    } else {
                        tL_userEmpty = new TLRPC.TL_userEmpty();
                        chat = null;
                    }
                }
                if (chat != null || tL_userEmpty != null) {
                    final boolean z4 = (tL_userEmpty == null || !tL_userEmpty.bot || MessagesController.isSupportUser(tL_userEmpty)) ? false : true;
                    if (i == 100) {
                        if (this.canPinCount != 0) {
                            if (!dialog3.pinned && getMessagesController().pinDialog(jLongValue2, true, null, -1L)) {
                                z3 = true;
                            }
                        } else if (dialog3.pinned && getMessagesController().pinDialog(jLongValue2, false, null, -1L)) {
                            z3 = true;
                        }
                    } else if (i == 101) {
                        if (this.canReadCount != 0) {
                            getMessagesController().markMentionsAsRead(jLongValue2);
                            getMessagesController().markDialogAsRead(jLongValue2, dialog3.top_message, dialog3.top_message, dialog3.last_message_date, false, 0, true, 0);
                        } else {
                            getMessagesController().markDialogAsUnread(jLongValue2, null, 0L);
                        }
                    } else if (i == 102 || i == 103) {
                        if (size != 1) {
                            if (i == 103 && this.canClearCacheCount != 0) {
                                getMessagesController().deleteDialog(jLongValue2, 2, false);
                            } else if (i == 103) {
                                getMessagesController().deleteDialog(jLongValue2, 1, false);
                            } else {
                                if (chat != null) {
                                    if (ChatObject.isNotInChat(chat)) {
                                        getMessagesController().deleteDialog(jLongValue2, 0, false);
                                    } else {
                                        getMessagesController().deleteUserFromChat((int) (-jLongValue2), getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId())), null);
                                    }
                                } else {
                                    getMessagesController().deleteDialog(jLongValue2, 0, false);
                                    if (z4) {
                                        getMessagesController().blockUser((int) jLongValue2);
                                    }
                                }
                                if (AndroidUtilities.isTablet()) {
                                    getNotificationCenter().postNotificationName(NotificationCenter.closeChats, Long.valueOf(jLongValue2));
                                }
                            }
                        } else {
                            final TLRPC.Chat chat2 = chat;
                            AlertsCreator.createClearOrDeleteDialogAlert(this, i == 103, chat, tL_userEmpty, i12 == 0, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$1t5jD5VnUniJ2Tu_We_lmQtOUXg
                                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
                                public final void run(boolean z5) {
                                    this.f$0.lambda$perfromSelectedDialogsAction$12$MryDialogsActivity(i, chat2, jLongValue2, z4, z5);
                                }
                            });
                            return;
                        }
                    } else if (i == 104) {
                        if (size == 1 && this.canMuteCount == 1) {
                            showDialog(AlertsCreator.createMuteAlert(getParentActivity(), jLongValue2), new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$dJgEJrp6Oe2y0kRugKJo9c_swos
                                @Override // android.content.DialogInterface.OnDismissListener
                                public final void onDismiss(DialogInterface dialogInterface) {
                                    this.f$0.lambda$perfromSelectedDialogsAction$13$MryDialogsActivity(dialogInterface);
                                }
                            });
                            return;
                        } else if (this.canUnmuteCount != 0) {
                            if (getMessagesController().isDialogMuted(jLongValue2)) {
                                getNotificationsController().setDialogNotificationsSettings(jLongValue2, 4);
                            }
                        } else if (!getMessagesController().isDialogMuted(jLongValue2)) {
                            getNotificationsController().setDialogNotificationsSettings(jLongValue2, 3);
                        }
                    }
                }
            }
            i11++;
            z3 = z3;
        }
        if (i == 100) {
            getMessagesController().reorderPinnedDialogs(this.folderId, null, 0L);
        }
        if (z3) {
            this.listView.smoothScrollToPosition(hasHiddenArchive() ? 1 : 0);
        }
        hideActionMode((i == 100 || i == 102) ? false : true);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$7$MryDialogsActivity(ArrayList copy) {
        getMessagesController().addDialogToFolder(copy, this.folderId == 0 ? 0 : 1, -1, null, 0L);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$8$MryDialogsActivity(int action, DialogInterface dialog1, int which) {
        getMessagesController().setDialogsInTransaction(true);
        perfromSelectedDialogsAction(action, false);
        getMessagesController().setDialogsInTransaction(false);
        MessagesController.getInstance(this.currentAccount).checkIfFolderEmpty(this.folderId);
        if (this.folderId != 0 && getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false).size() == 0) {
            this.listView.setEmptyView(null);
            this.progressView.setVisibility(4);
            finishFragment();
        }
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$9$MryDialogsActivity(int action, DialogInterface dialog1, int which) {
        perfromSelectedDialogsAction(action, false);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$10$MryDialogsActivity(int action, DialogInterface dialog1, int which) {
        perfromSelectedDialogsAction(action, false);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$12$MryDialogsActivity(final int action, final TLRPC.Chat chat, final long selectedDialog, final boolean isBot, final boolean param) {
        hideActionMode(false);
        if (action == 103 && ChatObject.isChannel(chat)) {
            if (!chat.megagroup || !TextUtils.isEmpty(chat.username)) {
                getMessagesController().deleteDialog(selectedDialog, 2, param);
                return;
            }
        }
        if (action == 102 && this.folderId != 0 && getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false).size() == 1) {
            this.progressView.setVisibility(4);
        }
        getUndoView().showWithAction(selectedDialog, action == 103 ? 0 : 1, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$ofmyQbS1uwktNcE1Br8U9gzUMRI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$11$MryDialogsActivity(action, selectedDialog, param, chat, isBot);
            }
        });
    }

    public /* synthetic */ void lambda$null$11$MryDialogsActivity(int action, long selectedDialog, boolean param, TLRPC.Chat chat, boolean isBot) {
        if (action == 103) {
            getMessagesController().deleteDialog(selectedDialog, 1, param);
            return;
        }
        if (chat == null) {
            getMessagesController().deleteDialog(selectedDialog, 0, param);
            if (isBot) {
                getMessagesController().blockUser((int) selectedDialog);
            }
        } else if (ChatObject.isNotInChat(chat)) {
            getMessagesController().deleteDialog(selectedDialog, 0, param);
        } else {
            TLRPC.User currentUser = getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId()));
            getMessagesController().deleteUserFromChat((int) (-selectedDialog), currentUser, null);
        }
        if (AndroidUtilities.isTablet()) {
            getNotificationCenter().postNotificationName(NotificationCenter.closeChats, Long.valueOf(selectedDialog));
        }
        MessagesController.getInstance(this.currentAccount).checkIfFolderEmpty(this.folderId);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$13$MryDialogsActivity(DialogInterface dialog12) {
        hideActionMode(true);
    }

    private void updateCounters(boolean hide) {
        int canUnarchiveCount;
        ArrayList<Long> selectedDialogs;
        TLRPC.User user;
        int canClearHistoryCount = 0;
        int canDeleteCount = 0;
        int canUnpinCount = 0;
        int canArchiveCount = 0;
        int canUnarchiveCount2 = 0;
        this.canUnmuteCount = 0;
        this.canMuteCount = 0;
        this.canPinCount = 0;
        this.canReadCount = 0;
        this.canClearCacheCount = 0;
        if (hide) {
            return;
        }
        ArrayList<Long> selectedDialogs2 = this.dialogsAdapter.getSelectedDialogs();
        int count = selectedDialogs2.size();
        int a = 0;
        while (a < count) {
            TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(selectedDialogs2.get(a).longValue());
            if (dialog == null) {
                selectedDialogs = selectedDialogs2;
            } else {
                long selectedDialog = dialog.id;
                boolean pinned = dialog.pinned;
                boolean hasUnread = dialog.unread_count != 0 || dialog.unread_mark;
                if (getMessagesController().isDialogMuted(selectedDialog)) {
                    this.canUnmuteCount++;
                } else {
                    this.canMuteCount++;
                }
                if (hasUnread) {
                    this.canReadCount++;
                }
                if (this.folderId == 1) {
                    canUnarchiveCount = canUnarchiveCount2 + 1;
                } else {
                    int canUnarchiveCount3 = canUnarchiveCount2;
                    if (selectedDialog != getUserConfig().getClientUserId() && selectedDialog != 777000 && !getMessagesController().isProxyDialog(selectedDialog, false)) {
                        canArchiveCount++;
                        canUnarchiveCount = canUnarchiveCount3;
                    } else {
                        canUnarchiveCount = canUnarchiveCount3;
                    }
                }
                int lower_id = (int) selectedDialog;
                int canArchiveCount2 = canArchiveCount;
                int canUnarchiveCount4 = canUnarchiveCount;
                int high_id = (int) (selectedDialog >> 32);
                if (DialogObject.isChannel(dialog)) {
                    TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(-lower_id));
                    selectedDialogs = selectedDialogs2;
                    if (getMessagesController().isProxyDialog(dialog.id, true)) {
                        this.canClearCacheCount++;
                    } else {
                        if (!pinned) {
                            this.canPinCount++;
                        } else {
                            canUnpinCount++;
                        }
                        if (chat == null || !chat.megagroup) {
                            this.canClearCacheCount++;
                            canDeleteCount++;
                        } else {
                            if (!TextUtils.isEmpty(chat.username)) {
                                this.canClearCacheCount++;
                            } else {
                                canClearHistoryCount++;
                            }
                            canDeleteCount++;
                        }
                    }
                    canArchiveCount = canArchiveCount2;
                    canUnarchiveCount2 = canUnarchiveCount4;
                } else {
                    selectedDialogs = selectedDialogs2;
                    boolean isChat = lower_id < 0 && high_id != 1;
                    TLRPC.User user2 = null;
                    if (isChat) {
                        getMessagesController().getChat(Integer.valueOf(-lower_id));
                    }
                    if (lower_id == 0) {
                        TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(high_id));
                        if (encryptedChat != null) {
                            user = getMessagesController().getUser(Integer.valueOf(encryptedChat.user_id));
                        } else {
                            user = new TLRPC.TL_userEmpty();
                        }
                    } else {
                        if (!isChat && lower_id > 0 && high_id != 1) {
                            user2 = getMessagesController().getUser(Integer.valueOf(lower_id));
                        }
                        user = user2;
                    }
                    if (user == null || !user.bot || !MessagesController.isSupportUser(user)) {
                    }
                    if (!pinned) {
                        this.canPinCount++;
                    } else {
                        canUnpinCount++;
                    }
                    canClearHistoryCount++;
                    canDeleteCount++;
                    canArchiveCount = canArchiveCount2;
                    canUnarchiveCount2 = canUnarchiveCount4;
                }
            }
            a++;
            selectedDialogs2 = selectedDialogs;
        }
        if (canDeleteCount != count) {
            this.deleteItem.setVisibility(8);
        } else {
            this.deleteItem.setVisibility(0);
        }
        int i = this.canClearCacheCount;
        if ((i != 0 && i != count) || (canClearHistoryCount != 0 && canClearHistoryCount != count)) {
            this.clearItem.setVisibility(8);
        } else {
            this.clearItem.setVisibility(0);
            if (this.canClearCacheCount != 0) {
                this.clearItem.setText(LocaleController.getString("ClearHistoryCache", R.string.ClearHistoryCache));
            } else {
                this.clearItem.setText(LocaleController.getString("ClearHistory", R.string.ClearHistory));
            }
        }
        if (this.canPinCount + canUnpinCount != count) {
            this.pinItem.setVisibility(8);
        } else {
            this.pinItem.setVisibility(0);
        }
        if (this.canUnmuteCount != 0) {
            this.muteItem.setIcon(R.drawable.msg_unmute);
            this.muteItem.setContentDescription(LocaleController.getString("ChatsUnmute", R.string.ChatsUnmute));
        } else {
            this.muteItem.setIcon(R.drawable.msg_mute);
            this.muteItem.setContentDescription(LocaleController.getString("ChatsMute", R.string.ChatsMute));
        }
        if (this.canReadCount != 0) {
            this.readItem.setTextAndIcon(LocaleController.getString("MarkAsRead", R.string.MarkAsRead), R.drawable.msg_markread);
        } else {
            this.readItem.setTextAndIcon(LocaleController.getString("MarkAsUnread", R.string.MarkAsUnread), R.drawable.msg_markunread);
        }
        if (this.canPinCount != 0) {
            this.pinItem.setIcon(R.drawable.msg_pin);
            this.pinItem.setContentDescription(LocaleController.getString("PinToTop", R.string.PinToTop));
        } else {
            this.pinItem.setIcon(R.drawable.msg_unpin);
            this.pinItem.setContentDescription(LocaleController.getString("UnpinFromTop", R.string.UnpinFromTop));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean validateSlowModeDialog(long dialogId) {
        int lowerId;
        TLRPC.Chat chat;
        ChatActivityEnterView chatActivityEnterView;
        if ((this.messagesCount <= 1 && ((chatActivityEnterView = this.commentView) == null || chatActivityEnterView.getVisibility() != 0 || TextUtils.isEmpty(this.commentView.getFieldText()))) || (lowerId = (int) dialogId) >= 0 || (chat = getMessagesController().getChat(Integer.valueOf(-lowerId))) == null || ChatObject.hasAdminRights(chat) || !chat.slowmode_enabled) {
            return true;
        }
        AlertsCreator.showSimpleAlert(this, LocaleController.getString("Slowmode", R.string.Slowmode), LocaleController.getString("SlowmodeSendError", R.string.SlowmodeSendError));
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showOrUpdateActionMode(TLRPC.Dialog dialog, View cell) {
        this.dialogsAdapter.addOrRemoveSelectedDialog(dialog.id, cell);
        ArrayList<Long> selectedDialogs = this.dialogsAdapter.getSelectedDialogs();
        boolean updateAnimated = false;
        if (this.actionBar.isActionModeShowed()) {
            if (selectedDialogs.isEmpty()) {
                hideActionMode(true);
                return;
            }
            updateAnimated = true;
        } else {
            this.actionBar.createActionMode();
            this.actionBar.showActionMode();
            if (!Theme.getCurrentTheme().isDark()) {
                this.actionBar.setBackButtonImage(R.drawable.back_black);
            }
            this.dialogsAdapter.setEdit(true);
            this.dialogsAdapter.notifyDataSetChanged();
            if (this.menuDrawable != null) {
                this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrGoBack", R.string.AccDescrGoBack));
            }
            if (getPinnedCount() > 1) {
                this.dialogsAdapter.onReorderStateChanged(true);
                updateVisibleRows(131072);
            }
            AnimatorSet animatorSet = new AnimatorSet();
            ArrayList<Animator> animators = new ArrayList<>();
            for (int a = 0; a < this.actionModeViews.size(); a++) {
                View view = this.actionModeViews.get(a);
                view.setPivotY(ActionBar.getCurrentActionBarHeight() / 2);
                AndroidUtilities.clearDrawableAnimation(view);
                animators.add(ObjectAnimator.ofFloat(view, (Property<View, Float>) View.SCALE_Y, 0.1f, 1.0f));
            }
            animatorSet.playTogether(animators);
            animatorSet.setDuration(250L);
            animatorSet.start();
            MenuDrawable menuDrawable = this.menuDrawable;
            if (menuDrawable != null) {
                menuDrawable.setRotateToBack(false);
                this.menuDrawable.setRotation(1.0f, true);
            } else {
                BackDrawable backDrawable = this.backDrawable;
                if (backDrawable != null) {
                    backDrawable.setRotation(1.0f, true);
                }
            }
        }
        updateCounters(false);
        this.selectedDialogsCountTextView.setNumber(selectedDialogs.size(), updateAnimated);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void closeSearch() {
        if (AndroidUtilities.isTablet()) {
            if (this.actionBar != null) {
                this.actionBar.closeSearchField();
            }
            TLObject tLObject = this.searchObject;
            if (tLObject != null) {
                this.dialogsSearchAdapter.putRecentSearch(this.searchDialogId, tLObject);
                this.searchObject = null;
                return;
            }
            return;
        }
        this.closeSearchFieldOnHide = true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public UndoView getUndoView() {
        if (this.undoView[0].getVisibility() == 0) {
            UndoView[] undoViewArr = this.undoView;
            UndoView old = undoViewArr[0];
            undoViewArr[0] = undoViewArr[1];
            undoViewArr[1] = old;
            old.hide(true, 2);
            FrameLayout contentView = (FrameLayout) this.fragmentView;
            contentView.removeView(this.undoView[0]);
            contentView.addView(this.undoView[0]);
        }
        return this.undoView[0];
    }

    private void updateProxyButton(boolean animated) {
        if (this.proxyDrawable == null) {
            return;
        }
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", 0);
        String proxyAddress = preferences.getString("proxy_ip", "");
        boolean z = preferences.getBoolean("proxy_enabled", false) && !TextUtils.isEmpty(proxyAddress);
        boolean proxyEnabled = z;
        if (z || (getMessagesController().blockedCountry && !SharedConfig.proxyList.isEmpty())) {
            if (!this.actionBar.isSearchFieldVisible()) {
                this.proxyItem.setVisibility(0);
            }
            ProxyDrawable proxyDrawable = this.proxyDrawable;
            int i = this.currentConnectionState;
            proxyDrawable.setConnected(proxyEnabled, i == 3 || i == 5, animated);
            this.proxyItemVisisble = true;
            return;
        }
        this.proxyItem.setVisibility(8);
        this.proxyItemVisisble = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSelectedCount() {
        if (this.commentView == null) {
            return;
        }
        if (!this.dialogsAdapter.hasSelectedDialogs()) {
            if (this.dialogsType == 3 && this.selectAlertString == null) {
                this.actionBar.setTitle(LocaleController.getString("ForwardTo", R.string.ForwardTo));
            } else {
                this.actionBar.setTitle(LocaleController.getString("SelectChat", R.string.SelectChat));
            }
            if (this.commentView.getTag() != null) {
                this.commentView.hidePopup(false);
                this.commentView.closeKeyboard();
                AnimatorSet animatorSet = new AnimatorSet();
                animatorSet.playTogether(ObjectAnimator.ofFloat(this.commentView, (Property<ChatActivityEnterView, Float>) View.TRANSLATION_Y, 0.0f, this.commentView.getMeasuredHeight()));
                animatorSet.setDuration(180L);
                animatorSet.setInterpolator(new DecelerateInterpolator());
                animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.11
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        MryDialogsActivity.this.commentView.setVisibility(8);
                    }
                });
                animatorSet.start();
                this.commentView.setTag(null);
                this.listView.requestLayout();
                return;
            }
            return;
        }
        if (this.commentView.getTag() == null) {
            this.commentView.setFieldText("");
            this.commentView.setVisibility(0);
            AnimatorSet animatorSet2 = new AnimatorSet();
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.commentView, (Property<ChatActivityEnterView, Float>) View.TRANSLATION_Y, this.commentView.getMeasuredHeight(), 0.0f));
            animatorSet2.setDuration(180L);
            animatorSet2.setInterpolator(new DecelerateInterpolator());
            animatorSet2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.chats.MryDialogsActivity.12
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    MryDialogsActivity.this.commentView.setTag(2);
                    MryDialogsActivity.this.commentView.requestLayout();
                }
            });
            animatorSet2.start();
            this.commentView.setTag(1);
        }
        this.actionBar.setTitle(LocaleController.formatPluralString("Recipient", this.dialogsAdapter.getSelectedDialogs().size()));
    }

    private void askForPermissons(boolean alert) {
        Activity activity = getParentActivity();
        if (activity == null) {
            return;
        }
        ArrayList<String> permissons = new ArrayList<>();
        if (activity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
            permissons.add(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE);
            permissons.add("android.permission.WRITE_EXTERNAL_STORAGE");
        }
        if (permissons.isEmpty()) {
            return;
        }
        String[] items = (String[]) permissons.toArray(new String[0]);
        try {
            activity.requestPermissions(items, 1);
        } catch (Exception e) {
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        super.onDialogDismiss(dialog);
        AlertDialog alertDialog = this.permissionDialog;
        if (alertDialog != null && dialog == alertDialog && getParentActivity() != null) {
            askForPermissons(false);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 1) {
            for (int a = 0; a < permissions.length; a++) {
                if (grantResults.length > a) {
                    String str = permissions[a];
                    byte b = -1;
                    if (str.hashCode() == 1365911975 && str.equals("android.permission.WRITE_EXTERNAL_STORAGE")) {
                        b = 0;
                    }
                    if (b == 0 && grantResults[a] == 0) {
                        ImageLoader.getInstance().checkMediaPaths();
                    }
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        MyDialogsAdapter myDialogsAdapter;
        if (id == NotificationCenter.dialogsNeedReload) {
            if (this.dialogsListFrozen) {
                return;
            }
            MyDialogsAdapter myDialogsAdapter2 = this.dialogsAdapter;
            if (myDialogsAdapter2 != null) {
                if (!myDialogsAdapter2.isDataSetChanged() && args.length <= 0) {
                    updateVisibleRows(2048);
                } else {
                    this.dialogsAdapter.notifyDataSetChanged();
                }
            }
            RecyclerListView recyclerListView = this.listView;
            if (recyclerListView != null) {
                try {
                    if (recyclerListView.getAdapter() == this.dialogsAdapter) {
                        this.searchEmptyView.setVisibility(8);
                        this.listView.setEmptyView(this.folderId == 0 ? this.progressView : null);
                        return;
                    }
                    if (this.searching && this.searchWas) {
                        this.listView.setEmptyView(this.searchEmptyView);
                    } else {
                        this.searchEmptyView.setVisibility(8);
                        this.listView.setEmptyView(null);
                    }
                    this.progressView.setVisibility(8);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.emojiDidLoad) {
            updateVisibleRows(0);
            return;
        }
        if (id == NotificationCenter.closeSearchByActiveAction) {
            if (this.actionBar != null) {
                this.actionBar.closeSearchField();
                return;
            }
            return;
        }
        if (id == NotificationCenter.proxySettingsChanged) {
            updateProxyButton(false);
            return;
        }
        if (id == NotificationCenter.updateInterfaces) {
            Integer mask = (Integer) args[0];
            updateVisibleRows(mask.intValue());
            if ((mask.intValue() & 4) != 0 && (myDialogsAdapter = this.dialogsAdapter) != null) {
                myDialogsAdapter.sortOnlineContacts(true);
                return;
            }
            return;
        }
        if (id == NotificationCenter.appDidLogout) {
            dialogsLoaded[this.currentAccount] = false;
            return;
        }
        if (id == NotificationCenter.encryptedChatUpdated) {
            updateVisibleRows(0);
            return;
        }
        if (id == NotificationCenter.contactsDidLoad) {
            if (this.dialogsListFrozen) {
                return;
            }
            if (this.dialogsType == 0 && getMessagesController().getDialogs(this.folderId).isEmpty()) {
                MyDialogsAdapter myDialogsAdapter3 = this.dialogsAdapter;
                if (myDialogsAdapter3 != null) {
                    myDialogsAdapter3.notifyDataSetChanged();
                    return;
                }
                return;
            }
            updateVisibleRows(0);
            return;
        }
        if (id == NotificationCenter.openedChatChanged) {
            if (this.dialogsType == 0 && AndroidUtilities.isTablet()) {
                boolean close = ((Boolean) args[1]).booleanValue();
                long dialog_id = ((Long) args[0]).longValue();
                if (!close) {
                    this.openedDialogId = dialog_id;
                } else if (dialog_id == this.openedDialogId) {
                    this.openedDialogId = 0L;
                }
                MyDialogsAdapter myDialogsAdapter4 = this.dialogsAdapter;
                if (myDialogsAdapter4 != null) {
                    myDialogsAdapter4.setOpenedDialogId(this.openedDialogId);
                }
                updateVisibleRows(512);
                return;
            }
            return;
        }
        if (id == NotificationCenter.notificationsSettingsUpdated) {
            updateVisibleRows(0);
            return;
        }
        if (id == NotificationCenter.messageReceivedByAck || id == NotificationCenter.messageReceivedByServer || id == NotificationCenter.messageSendError) {
            updateVisibleRows(4096);
            return;
        }
        if (id == NotificationCenter.didSetPasscode) {
            updatePasscodeButton();
            return;
        }
        if (id == NotificationCenter.needReloadRecentDialogsSearch) {
            DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
            if (dialogsSearchAdapter != null) {
                dialogsSearchAdapter.loadRecentSearch();
                return;
            }
            return;
        }
        if (id == NotificationCenter.replyMessagesDidLoad) {
            updateVisibleRows(32768);
            return;
        }
        if (id == NotificationCenter.reloadHints) {
            DialogsSearchAdapter dialogsSearchAdapter2 = this.dialogsSearchAdapter;
            if (dialogsSearchAdapter2 != null) {
                dialogsSearchAdapter2.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.didUpdateConnectionState) {
            int state = AccountInstance.getInstance(account).getConnectionsManager().getConnectionState();
            if (this.currentConnectionState != state) {
                this.currentConnectionState = state;
                updateProxyButton(true);
                return;
            }
            return;
        }
        if (id != NotificationCenter.dialogsUnreadCounterChanged) {
            if (id == NotificationCenter.needDeleteDialog) {
                if (this.fragmentView == null || this.isPaused) {
                    return;
                }
                final long dialogId = ((Long) args[0]).longValue();
                final TLRPC.Chat chat = (TLRPC.Chat) args[2];
                final boolean revoke = ((Boolean) args[3]).booleanValue();
                Runnable deleteRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$MqqLjxXZn11XccLe3qtSLN4zC9k
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$didReceivedNotification$14$MryDialogsActivity(chat, dialogId, revoke);
                    }
                };
                if (this.undoView[0] != null) {
                    getUndoView().showWithAction(dialogId, 1, deleteRunnable);
                    return;
                } else {
                    deleteRunnable.run();
                    return;
                }
            }
            if (id == NotificationCenter.folderBecomeEmpty) {
                int fid = ((Integer) args[0]).intValue();
                int i = this.folderId;
                if (i == fid && i != 0) {
                    finishFragment();
                }
            }
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$14$MryDialogsActivity(TLRPC.Chat chat, long dialogId, boolean revoke) {
        if (chat == null || ChatObject.isNotInChat(chat)) {
            getMessagesController().deleteDialog(dialogId, 0, revoke);
        } else {
            getMessagesController().deleteUserFromChat((int) (-dialogId), getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId())), null, false, revoke);
        }
        MessagesController.getInstance(this.currentAccount).checkIfFolderEmpty(this.folderId);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setDialogsListFrozen(boolean frozen) {
        if (this.dialogsListFrozen == frozen) {
            return;
        }
        if (frozen) {
            frozenDialogsList = new ArrayList<>(getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false));
        } else {
            frozenDialogsList = null;
        }
        this.dialogsListFrozen = frozen;
        this.dialogsAdapter.setDialogsListFrozen(frozen);
        if (!frozen) {
            this.dialogsAdapter.notifyDataSetChanged();
        }
    }

    public static ArrayList<TLRPC.Dialog> getDialogsArray(int currentAccount, int dialogsType, int folderId, boolean frozen) {
        ArrayList<TLRPC.Dialog> arrayList;
        if (frozen && (arrayList = frozenDialogsList) != null) {
            return arrayList;
        }
        MessagesController messagesController = AccountInstance.getInstance(currentAccount).getMessagesController();
        if (dialogsType == 0) {
            return messagesController.getDialogs(folderId);
        }
        if (dialogsType == 1) {
            return messagesController.dialogsServerOnly;
        }
        if (dialogsType == 2) {
            return messagesController.dialogsCanAddUsers;
        }
        if (dialogsType == 3) {
            return messagesController.dialogsForward;
        }
        if (dialogsType == 4) {
            return messagesController.dialogsUsersOnly;
        }
        if (dialogsType == 5) {
            return messagesController.dialogsChannelsOnly;
        }
        if (dialogsType == 6) {
            return messagesController.dialogsGroupsOnly;
        }
        return null;
    }

    public void setSideMenu(RecyclerView recyclerView) {
        this.sideMenu = recyclerView;
        recyclerView.setBackgroundColor(Theme.getColor(Theme.key_chats_menuBackground));
        this.sideMenu.setGlowColor(Theme.getColor(Theme.key_chats_menuBackground));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updatePasscodeButton() {
        if (this.passcodeItem == null) {
            return;
        }
        if (SharedConfig.passcodeHash.length() != 0 && !this.searching) {
            this.passcodeItem.setVisibility(0);
            if (SharedConfig.appLocked) {
                this.passcodeItem.setIcon(R.drawable.lock_close);
                this.passcodeItem.setContentDescription(LocaleController.getString("AccDescrPasscodeUnlock", R.string.AccDescrPasscodeUnlock));
                return;
            } else {
                this.passcodeItem.setIcon(R.drawable.lock_open);
                this.passcodeItem.setContentDescription(LocaleController.getString("AccDescrPasscodeLock", R.string.AccDescrPasscodeLock));
                return;
            }
        }
        this.passcodeItem.setVisibility(8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateDialogIndices() {
        int index;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView == null || recyclerListView.getAdapter() != this.dialogsAdapter) {
            return;
        }
        ArrayList<TLRPC.Dialog> dialogs = getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false);
        int count = this.listView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            if (child instanceof DialogCell) {
                DialogCell dialogCell = (DialogCell) child;
                TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(dialogCell.getDialogId());
                if (dialog != null && (index = dialogs.indexOf(dialog)) >= 0) {
                    dialogCell.setDialogIndex(index);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateVisibleRows(int mask) {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView == null || this.dialogsListFrozen) {
            return;
        }
        int count = recyclerListView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            if (child instanceof DialogCell) {
                if (this.listView.getAdapter() != this.dialogsSearchAdapter) {
                    DialogCell cell = (DialogCell) child;
                    if ((131072 & mask) != 0) {
                        cell.onReorderStateChanged(this.actionBar.isActionModeShowed(), true);
                    }
                    if ((65536 & mask) != 0) {
                        cell.setChecked(false, (mask & 8192) != 0);
                    } else {
                        if ((mask & 2048) != 0) {
                            cell.checkCurrentDialogIndex(this.dialogsListFrozen);
                            if (this.dialogsType == 0 && AndroidUtilities.isTablet()) {
                                cell.setDialogSelected(cell.getDialogId() == this.openedDialogId);
                            }
                        } else if ((mask & 512) != 0) {
                            if (this.dialogsType == 0 && AndroidUtilities.isTablet()) {
                                cell.setDialogSelected(cell.getDialogId() == this.openedDialogId);
                            }
                        } else {
                            cell.update(mask);
                        }
                        ArrayList<Long> selectedDialogs = this.dialogsAdapter.getSelectedDialogs();
                        if (selectedDialogs != null) {
                            cell.setChecked(selectedDialogs.contains(Long.valueOf(cell.getDialogId())), false);
                        }
                    }
                }
            } else if (child instanceof UserCell) {
                ((UserCell) child).update(mask);
            } else if (child instanceof ProfileSearchCell) {
                ((ProfileSearchCell) child).update(mask);
            } else if (child instanceof RecyclerListView) {
                RecyclerListView innerListView = (RecyclerListView) child;
                int count2 = innerListView.getChildCount();
                for (int b = 0; b < count2; b++) {
                    View child2 = innerListView.getChildAt(b);
                    if (child2 instanceof HintDialogCell) {
                        ((HintDialogCell) child2).update(mask);
                    }
                }
            }
        }
    }

    public void setDelegate(DialogsActivityDelegate dialogsActivityDelegate) {
        this.delegate = dialogsActivityDelegate;
    }

    public void setSearchString(String string) {
        this.searchString = string;
    }

    public boolean isMainDialogList() {
        return this.delegate == null && this.searchString == null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void didSelectResult(final long dialog_id, boolean useAlert, boolean param) {
        if (this.addToGroupAlertString == null && this.checkCanWrite && ((int) dialog_id) < 0) {
            TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(-((int) dialog_id)));
            if (ChatObject.isChannel(chat) && !chat.megagroup && (this.cantSendToChannels || !ChatObject.isCanWriteToChannel(-((int) dialog_id), this.currentAccount))) {
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.getString("ChannelCantSendMessage", R.string.ChannelCantSendMessage));
                builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(builder.create());
                return;
            }
        }
        if (useAlert && ((this.selectAlertString != null && this.selectAlertStringGroup != null) || this.addToGroupAlertString != null)) {
            if (getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
            builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
            int lower_part = (int) dialog_id;
            int high_id = (int) (dialog_id >> 32);
            if (lower_part != 0) {
                if (lower_part == getUserConfig().getClientUserId()) {
                    builder2.setMessage(LocaleController.formatStringSimple(this.selectAlertStringGroup, LocaleController.getString("SavedMessages", R.string.SavedMessages)));
                } else if (lower_part > 0) {
                    TLRPC.User user = getMessagesController().getUser(Integer.valueOf(lower_part));
                    if (user == null) {
                        return;
                    } else {
                        builder2.setMessage(LocaleController.formatStringSimple(this.selectAlertString, UserObject.getName(user)));
                    }
                } else if (lower_part < 0) {
                    TLRPC.Chat chat2 = getMessagesController().getChat(Integer.valueOf(-lower_part));
                    if (chat2 == null) {
                        return;
                    }
                    String str = this.addToGroupAlertString;
                    if (str != null) {
                        builder2.setMessage(LocaleController.formatStringSimple(str, chat2.title));
                    } else {
                        builder2.setMessage(LocaleController.formatStringSimple(this.selectAlertStringGroup, chat2.title));
                    }
                }
            } else {
                TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(getMessagesController().getEncryptedChat(Integer.valueOf(high_id)).user_id));
                if (user2 == null) {
                    return;
                } else {
                    builder2.setMessage(LocaleController.formatStringSimple(this.selectAlertString, UserObject.getName(user2)));
                }
            }
            builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$F1FJTn3ZmxQ-waRVSbA1bs7oqDU
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$didSelectResult$15$MryDialogsActivity(dialog_id, dialogInterface, i);
                }
            });
            builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder2.create());
            return;
        }
        if (this.delegate != null) {
            ArrayList<Long> dids = new ArrayList<>();
            dids.add(Long.valueOf(dialog_id));
            this.delegate.didSelectDialogs(this, dids, null, param);
            if (this.resetDelegate) {
                this.delegate = null;
                return;
            }
            return;
        }
        finishFragment();
    }

    public /* synthetic */ void lambda$didSelectResult$15$MryDialogsActivity(long dialog_id, DialogInterface dialogInterface, int i) {
        didSelectResult(dialog_id, false, false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    public void hideTitle(View rootView) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(rootView, "translationY", 0.0f, -ActionBar.getCurrentActionBarHeight());
        animator.setDuration(300L);
        animator.start();
        this.actionBar.setVisibility(4);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    public void showTitle(View rootView) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(rootView, "translationY", -ActionBar.getCurrentActionBarHeight(), 0.0f);
        animator.start();
        this.actionBar.setVisibility(0);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$MryDialogsActivity$ie2iYiknWqc23iLAUw7TD0MuM3Y
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$16$MryDialogsActivity();
            }
        };
        ArrayList<ThemeDescription> arrayList = new ArrayList<>();
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
        DialogCell dialogCell = this.movingView;
        if (dialogCell != null) {
            arrayList.add(new ThemeDescription(dialogCell, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
        }
        if (this.folderId == 0) {
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
            arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, new Drawable[]{Theme.dialogs_holidayDrawable}, null, Theme.key_actionBarDefaultTitle));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder));
        } else {
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefaultArchived));
            arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefaultArchived));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultArchivedIcon));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, new Drawable[]{Theme.dialogs_holidayDrawable}, null, Theme.key_actionBarDefaultArchivedTitle));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultArchivedSelector));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultArchivedSearch));
            arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultArchivedSearchPlaceholder));
        }
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultIcon));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_BACKGROUND, null, null, null, null, Theme.key_actionBarActionModeDefault));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_TOPBACKGROUND, null, null, null, null, Theme.key_actionBarActionModeDefaultTop));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultSelector));
        arrayList.add(new ThemeDescription(this.selectedDialogsCountTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultIcon));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider));
        arrayList.add(new ThemeDescription(this.searchEmptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder));
        arrayList.add(new ThemeDescription(this.searchEmptyView, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{DialogsEmptyCell.class}, new String[]{"emptyTextView1"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_nameMessage_threeLines));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{DialogsEmptyCell.class}, new String[]{"emptyTextView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_message));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class, ProfileSearchCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundSaved));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundArchived));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundArchivedHidden));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_countPaint, null, null, Theme.key_chats_unreadCounter));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_countGrayPaint, null, null, Theme.key_chats_unreadCounterMuted));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_countTextPaint, null, null, Theme.key_chats_unreadCounterText));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class, ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_namePaint, Theme.dialogs_searchNamePaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_name));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class, ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_nameEncryptedPaint, Theme.dialogs_searchNameEncryptedPaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_secretName));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class, ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_lockDrawable}, null, Theme.key_chats_secretIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class, ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_groupDrawable, Theme.dialogs_broadcastDrawable, Theme.dialogs_botDrawable}, null, Theme.key_chats_nameIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class, ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_scamDrawable}, null, Theme.key_chats_draft));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, new Drawable[]{Theme.dialogs_pinnedDrawable, Theme.dialogs_reorderDrawable}, null, Theme.key_chats_pinnedIcon));
        if (SharedConfig.useThreeLinesLayout) {
            arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_messagePaint, null, null, Theme.key_chats_message_threeLines));
        } else {
            arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_messagePaint, null, null, Theme.key_chats_message));
        }
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_messageNamePaint, null, null, Theme.key_chats_nameMessage_threeLines));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, null, null, Theme.key_chats_draft));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_chats_nameMessage));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_chats_draft));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_chats_attachMessage));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_chats_nameArchived));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_chats_nameMessageArchived));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_chats_nameMessageArchived_threeLines));
        arrayList.add(new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_chats_messageArchived));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_messagePrintingPaint, null, null, Theme.key_chats_actionMessage));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_timePaint, null, null, Theme.key_chats_date));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_pinnedPaint, null, null, Theme.key_chats_pinnedOverlay));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_tabletSeletedPaint, null, null, Theme.key_chats_tabletSelectedOverlay));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, new Drawable[]{Theme.dialogs_checkDrawable}, null, Theme.key_chats_sentCheck));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, new Drawable[]{Theme.dialogs_checkReadDrawable, Theme.dialogs_halfCheckDrawable}, null, Theme.key_chats_sentReadCheck));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, new Drawable[]{Theme.dialogs_clockDrawable}, null, Theme.key_chats_sentClock));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, Theme.dialogs_errorPaint, null, null, Theme.key_chats_sentError));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, new Drawable[]{Theme.dialogs_errorDrawable}, null, Theme.key_chats_sentErrorIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class, ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedCheckDrawable}, null, Theme.key_chats_verifiedCheck));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class, ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedDrawable}, null, Theme.key_chats_verifiedBackground));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, new Drawable[]{Theme.dialogs_muteDrawable}, null, Theme.key_chats_muteIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, new Drawable[]{Theme.dialogs_mentionDrawable}, null, Theme.key_chats_mentionIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, null, null, Theme.key_chats_archivePinBackground));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, null, null, null, Theme.key_chats_archiveBackground));
        if (SharedConfig.archiveHidden) {
            arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveAvatarDrawable}, "Arrow1", Theme.key_avatar_backgroundArchivedHidden));
            arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveAvatarDrawable}, "Arrow2", Theme.key_avatar_backgroundArchivedHidden));
        } else {
            arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveAvatarDrawable}, "Arrow1", Theme.key_avatar_backgroundArchived));
            arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveAvatarDrawable}, "Arrow2", Theme.key_avatar_backgroundArchived));
        }
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveAvatarDrawable}, "Box2", Theme.key_avatar_text));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveAvatarDrawable}, "Box1", Theme.key_avatar_text));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_pinArchiveDrawable}, "Arrow", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_pinArchiveDrawable}, "Line", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_unpinArchiveDrawable}, "Arrow", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_unpinArchiveDrawable}, "Line", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveDrawable}, "Arrow", Theme.key_chats_archiveBackground));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveDrawable}, "Box2", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_archiveDrawable}, "Box1", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_unarchiveDrawable}, "Arrow1", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_unarchiveDrawable}, "Arrow2", Theme.key_chats_archivePinBackground));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_unarchiveDrawable}, "Box2", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{DialogCell.class}, new RLottieDrawable[]{Theme.dialogs_unarchiveDrawable}, "Box1", Theme.key_chats_archiveIcon));
        arrayList.add(new ThemeDescription(this.sideMenu, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_chats_menuBackground));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerProfileCell.class}, null, null, null, Theme.key_chats_menuName));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerProfileCell.class}, null, null, null, Theme.key_chats_menuPhone));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerProfileCell.class}, null, null, null, Theme.key_chats_menuPhoneCats));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerProfileCell.class}, null, null, null, Theme.key_chats_menuCloudBackgroundCats));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerProfileCell.class}, null, null, null, Theme.key_chat_serviceBackground));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerProfileCell.class}, null, null, null, Theme.key_chats_menuTopShadow));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerProfileCell.class}, null, null, null, Theme.key_chats_menuTopShadowCats));
        arrayList.add(new ThemeDescription(this.sideMenu, ThemeDescription.FLAG_CHECKTAG | ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{DrawerProfileCell.class}, null, null, cellDelegate, Theme.key_chats_menuTopBackgroundCats));
        arrayList.add(new ThemeDescription(this.sideMenu, ThemeDescription.FLAG_CHECKTAG | ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{DrawerProfileCell.class}, null, null, cellDelegate, Theme.key_chats_menuTopBackground));
        arrayList.add(new ThemeDescription(this.sideMenu, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{DrawerActionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_menuItemIcon));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerActionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_menuItemText));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerUserCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_menuItemText));
        arrayList.add(new ThemeDescription(this.sideMenu, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{DrawerUserCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_unreadCounterText));
        arrayList.add(new ThemeDescription(this.sideMenu, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{DrawerUserCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_unreadCounter));
        arrayList.add(new ThemeDescription(this.sideMenu, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{DrawerUserCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_menuBackground));
        arrayList.add(new ThemeDescription(this.sideMenu, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{DrawerAddCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_menuItemIcon));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DrawerAddCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_menuItemText));
        arrayList.add(new ThemeDescription(this.sideMenu, 0, new Class[]{DividerCell.class}, Theme.dividerPaint, null, null, Theme.key_divider));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{LoadingCell.class}, new String[]{"progressBar"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_progressCircle));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_offlinePaint, null, null, Theme.key_windowBackgroundWhiteGrayText3));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_onlinePaint, null, null, Theme.key_windowBackgroundWhiteBlueText3));
        arrayList.add(new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{HashtagSearchCell.class}, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
        arrayList.add(new ThemeDescription(this.progressView, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle));
        MyDialogsAdapter myDialogsAdapter = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(myDialogsAdapter != null ? myDialogsAdapter.getArchiveHintCellPager() : null, 0, new Class[]{ArchiveHintInnerCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_nameMessage_threeLines));
        MyDialogsAdapter myDialogsAdapter2 = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(myDialogsAdapter2 != null ? myDialogsAdapter2.getArchiveHintCellPager() : null, 0, new Class[]{ArchiveHintInnerCell.class}, new String[]{"imageView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_unreadCounter));
        MyDialogsAdapter myDialogsAdapter3 = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(myDialogsAdapter3 != null ? myDialogsAdapter3.getArchiveHintCellPager() : null, 0, new Class[]{ArchiveHintInnerCell.class}, new String[]{"headerTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_nameMessage_threeLines));
        MyDialogsAdapter myDialogsAdapter4 = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(myDialogsAdapter4 != null ? myDialogsAdapter4.getArchiveHintCellPager() : null, 0, new Class[]{ArchiveHintInnerCell.class}, new String[]{"messageTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_message));
        MyDialogsAdapter myDialogsAdapter5 = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(myDialogsAdapter5 != null ? myDialogsAdapter5.getArchiveHintCellPager() : null, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefaultArchived));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGray));
        DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
        arrayList.add(new ThemeDescription(dialogsSearchAdapter != null ? dialogsSearchAdapter.getInnerListView() : null, 0, new Class[]{HintDialogCell.class}, Theme.dialogs_countPaint, null, null, Theme.key_chats_unreadCounter));
        DialogsSearchAdapter dialogsSearchAdapter2 = this.dialogsSearchAdapter;
        arrayList.add(new ThemeDescription(dialogsSearchAdapter2 != null ? dialogsSearchAdapter2.getInnerListView() : null, 0, new Class[]{HintDialogCell.class}, Theme.dialogs_countGrayPaint, null, null, Theme.key_chats_unreadCounterMuted));
        DialogsSearchAdapter dialogsSearchAdapter3 = this.dialogsSearchAdapter;
        arrayList.add(new ThemeDescription(dialogsSearchAdapter3 != null ? dialogsSearchAdapter3.getInnerListView() : null, 0, new Class[]{HintDialogCell.class}, Theme.dialogs_countTextPaint, null, null, Theme.key_chats_unreadCounterText));
        DialogsSearchAdapter dialogsSearchAdapter4 = this.dialogsSearchAdapter;
        arrayList.add(new ThemeDescription(dialogsSearchAdapter4 != null ? dialogsSearchAdapter4.getInnerListView() : null, 0, new Class[]{HintDialogCell.class}, Theme.dialogs_archiveTextPaint, null, null, Theme.key_chats_archiveText));
        DialogsSearchAdapter dialogsSearchAdapter5 = this.dialogsSearchAdapter;
        arrayList.add(new ThemeDescription(dialogsSearchAdapter5 != null ? dialogsSearchAdapter5.getInnerListView() : null, 0, new Class[]{HintDialogCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
        DialogsSearchAdapter dialogsSearchAdapter6 = this.dialogsSearchAdapter;
        arrayList.add(new ThemeDescription(dialogsSearchAdapter6 != null ? dialogsSearchAdapter6.getInnerListView() : null, 0, new Class[]{HintDialogCell.class}, null, null, null, Theme.key_chats_onlineCircle));
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, new Class[]{FragmentContextView.class}, new String[]{"frameLayout"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerBackground));
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{FragmentContextView.class}, new String[]{"playButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerPlayPause));
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{FragmentContextView.class}, new String[]{"titleTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerTitle));
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_FASTSCROLL, new Class[]{FragmentContextView.class}, new String[]{"titleTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerPerformer));
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{FragmentContextView.class}, new String[]{"closeButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerClose));
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, new Class[]{FragmentContextView.class}, new String[]{"frameLayout"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_returnToCallBackground));
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{FragmentContextView.class}, new String[]{"titleTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_returnToCallText));
        arrayList.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueText2));
        int a = 0;
        while (true) {
            UndoView[] undoViewArr = this.undoView;
            if (a < undoViewArr.length) {
                arrayList.add(new ThemeDescription(undoViewArr[a], ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_undo_background));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"undoImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_cancelColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"undoTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_cancelColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"infoTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"subinfoTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"textPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"progressPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "info1", Theme.key_undo_background));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "info2", Theme.key_undo_background));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc12", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc11", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc10", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc9", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc8", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc7", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc6", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc5", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc4", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc3", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc2", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "luc1", Theme.key_undo_infoColor));
                arrayList.add(new ThemeDescription(this.undoView[a], 0, new Class[]{UndoView.class}, new String[]{"leftImageView"}, "Oval", Theme.key_undo_infoColor));
                a++;
            } else {
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogBackgroundGray));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextBlack));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextLink));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogLinkSelection));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextBlue));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextBlue2));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextBlue3));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextBlue4));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextRed));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextRed2));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextGray));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextGray2));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextGray3));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextGray4));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogIcon));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogRedIcon));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogTextHint));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogInputField));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogInputFieldActivated));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogCheckboxSquareBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogCheckboxSquareCheck));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogCheckboxSquareUnchecked));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogCheckboxSquareDisabled));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogRadioBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogRadioBackgroundChecked));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogProgressCircle));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogButton));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogButtonSelector));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogScrollGlow));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogRoundCheckBox));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogRoundCheckBoxCheck));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogBadgeBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogBadgeText));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogLineProgress));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogLineProgressBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogGrayLine));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialog_inlineProgressBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialog_inlineProgress));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogSearchBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogSearchHint));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogSearchIcon));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogSearchText));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogFloatingButton));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogFloatingIcon));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_dialogShadowLine));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_sheet_scrollUp));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_sheet_other));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_actionBar));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_actionBarSelector));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_actionBarTitle));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_actionBarTop));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_actionBarSubtitle));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_actionBarItems));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_background));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_time));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_progressBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_progressCachedBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_progress));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_placeholder));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_placeholderBackground));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_button));
                arrayList.add(new ThemeDescription(null, 0, null, null, null, null, Theme.key_player_buttonActive));
                return (ThemeDescription[]) arrayList.toArray(new ThemeDescription[0]);
            }
        }
    }

    public /* synthetic */ void lambda$getThemeDescriptions$16$MryDialogsActivity() {
        RecyclerListView recyclerListView;
        RecyclerListView recyclerListView2 = this.listView;
        if (recyclerListView2 != null) {
            int count = recyclerListView2.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof ProfileSearchCell) {
                    ((ProfileSearchCell) child).update(0);
                } else if (child instanceof DialogCell) {
                    ((DialogCell) child).update(0);
                }
            }
        }
        DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
        if (dialogsSearchAdapter != null && (recyclerListView = dialogsSearchAdapter.getInnerListView()) != null) {
            int count2 = recyclerListView.getChildCount();
            for (int a2 = 0; a2 < count2; a2++) {
                View child2 = recyclerListView.getChildAt(a2);
                if (child2 instanceof HintDialogCell) {
                    ((HintDialogCell) child2).update();
                }
            }
        }
        RecyclerView recyclerView = this.sideMenu;
        if (recyclerView != null) {
            View child3 = recyclerView.getChildAt(0);
            if (child3 instanceof DrawerProfileCell) {
                DrawerProfileCell profileCell = (DrawerProfileCell) child3;
                profileCell.applyBackground(true);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchExpand() {
        this.searching = true;
        ActionBarMenuItem actionBarMenuItem = this.switchItem;
        if (actionBarMenuItem != null) {
            actionBarMenuItem.setVisibility(8);
        }
        ActionBarMenuItem actionBarMenuItem2 = this.proxyItem;
        if (actionBarMenuItem2 != null && this.proxyItemVisisble) {
            actionBarMenuItem2.setVisibility(8);
        }
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null && this.searchString != null) {
            recyclerListView.setEmptyView(this.searchEmptyView);
            this.progressView.setVisibility(8);
        }
        updatePasscodeButton();
        this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrGoBack", R.string.AccDescrGoBack));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public boolean canCollapseSearch() {
        ActionBarMenuItem actionBarMenuItem = this.switchItem;
        if (actionBarMenuItem != null) {
            actionBarMenuItem.setVisibility(0);
        }
        ActionBarMenuItem actionBarMenuItem2 = this.proxyItem;
        if (actionBarMenuItem2 != null && this.proxyItemVisisble) {
            actionBarMenuItem2.setVisibility(0);
        }
        return this.searchString == null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchCollapse() {
        this.searching = false;
        this.searchWas = false;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            recyclerListView.setEmptyView(this.folderId == 0 ? this.progressView : null);
            this.searchEmptyView.setVisibility(8);
            RecyclerView.Adapter adapter = this.listView.getAdapter();
            MyDialogsAdapter myDialogsAdapter = this.dialogsAdapter;
            if (adapter != myDialogsAdapter) {
                this.listView.setAdapter(myDialogsAdapter);
                this.dialogsAdapter.notifyDataSetChanged();
            }
        }
        DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
        if (dialogsSearchAdapter != null) {
            dialogsSearchAdapter.searchDialogs(null);
        }
        updatePasscodeButton();
        if (this.menuDrawable != null) {
            this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrOpenMenu", R.string.AccDescrOpenMenu));
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onTextChange(String text) {
        DialogsSearchAdapter dialogsSearchAdapter;
        if (text.length() != 0 || ((dialogsSearchAdapter = this.dialogsSearchAdapter) != null && dialogsSearchAdapter.hasRecentRearch())) {
            this.searchWas = true;
            if (this.dialogsSearchAdapter != null) {
                RecyclerView.Adapter adapter = this.listView.getAdapter();
                DialogsSearchAdapter dialogsSearchAdapter2 = this.dialogsSearchAdapter;
                if (adapter != dialogsSearchAdapter2) {
                    this.listView.setAdapter(dialogsSearchAdapter2);
                    this.dialogsSearchAdapter.notifyDataSetChanged();
                }
            }
            if (this.searchEmptyView != null && this.listView.getEmptyView() != this.searchEmptyView) {
                this.progressView.setVisibility(8);
                this.listView.setEmptyView(this.searchEmptyView);
            }
        }
        DialogsSearchAdapter dialogsSearchAdapter3 = this.dialogsSearchAdapter;
        if (dialogsSearchAdapter3 != null) {
            dialogsSearchAdapter3.searchDialogs(text);
        }
    }
}
