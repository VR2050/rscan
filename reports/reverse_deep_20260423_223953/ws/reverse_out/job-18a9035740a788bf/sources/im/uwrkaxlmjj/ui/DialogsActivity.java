package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
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
import android.view.ViewOutlineProvider;
import android.view.ViewTreeObserver;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.LinearSmoothScrollerMiddle;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.premission.PermissionUtils;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
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
import im.uwrkaxlmjj.messenger.utils.RegexUtils;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuSubItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BackDrawable;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.MenuDrawable;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.adapters.DialogsAdapter;
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
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
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
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DialogsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int archive = 105;
    private static final int clear = 103;
    private static final int delete = 102;
    public static boolean[] dialogsLoaded = new boolean[3];
    private static ArrayList<TLRPC.Dialog> frozenDialogsList = null;
    private static MessageObject messageObject = null;
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
    private int currentConnectionState;
    private DialogsActivityDelegate delegate;
    private ActionBarMenuItem deleteItem;
    private int dialogChangeFinished;
    private int dialogInsertFinished;
    private int dialogRemoveFinished;
    private DialogsAdapter dialogsAdapter;
    private DialogsItemAnimator dialogsItemAnimator;
    private boolean dialogsListFrozen;
    private DialogsSearchAdapter dialogsSearchAdapter;
    private int dialogsType;
    private ImageView floatingButton;
    private FrameLayout floatingButtonContainer;
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
        void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList<Long> arrayList, CharSequence charSequence, boolean z);
    }

    static /* synthetic */ int access$3508(DialogsActivity x0) {
        int i = x0.lastItemsCount;
        x0.lastItemsCount = i + 1;
        return i;
    }

    static /* synthetic */ int access$3510(DialogsActivity x0) {
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
            measureChildWithMargins(DialogsActivity.this.actionBar, widthMeasureSpec, 0, heightMeasureSpec, 0);
            int keyboardSize = getKeyboardHeight();
            int childCount = getChildCount();
            if (DialogsActivity.this.commentView != null) {
                measureChildWithMargins(DialogsActivity.this.commentView, widthMeasureSpec, 0, heightMeasureSpec, 0);
                Object tag = DialogsActivity.this.commentView.getTag();
                if (tag != null && tag.equals(2)) {
                    if (keyboardSize <= AndroidUtilities.dp(20.0f) && !AndroidUtilities.isInMultiwindow) {
                        heightSize2 -= DialogsActivity.this.commentView.getEmojiPadding();
                    }
                    this.inputFieldHeight = DialogsActivity.this.commentView.getMeasuredHeight();
                } else {
                    this.inputFieldHeight = 0;
                }
            }
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child != null && child.getVisibility() != 8 && child != DialogsActivity.this.commentView && child != DialogsActivity.this.actionBar) {
                    if (child != DialogsActivity.this.progressView && child != DialogsActivity.this.searchEmptyView) {
                        if (DialogsActivity.this.commentView != null && DialogsActivity.this.commentView.isPopupView(child)) {
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
            Object tag = DialogsActivity.this.commentView != null ? DialogsActivity.this.commentView.getTag() : null;
            int i = 2;
            int paddingBottom = (tag == null || !tag.equals(2) || getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow) ? 0 : DialogsActivity.this.commentView.getEmojiPadding();
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
                    if (DialogsActivity.this.commentView != null && DialogsActivity.this.commentView.isPopupView(child)) {
                        childTop = AndroidUtilities.isInMultiwindow ? (DialogsActivity.this.commentView.getTop() - child.getMeasuredHeight()) + AndroidUtilities.dp(1.0f) : DialogsActivity.this.commentView.getBottom();
                    }
                    child.layout(childLeft, childTop, childLeft + width, childTop + height);
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
                    int currentPosition = DialogsActivity.this.layoutManager.findFirstVisibleItemPosition();
                    DialogsActivity.this.startedScrollAtTop = currentPosition <= 1;
                } else if (DialogsActivity.this.actionBar.isActionModeShowed()) {
                    DialogsActivity.this.allowMoving = true;
                }
                DialogsActivity.this.totalConsumedAmount = 0;
                DialogsActivity.this.allowScrollToHiddenView = false;
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
            if (DialogsActivity.this.waitingForDialogsAnimationEnd() || (DialogsActivity.this.parentLayout != null && DialogsActivity.this.parentLayout.isInPreviewMode())) {
                return 0;
            }
            if (!this.swipingFolder || !this.swipeFolderBack) {
                if (DialogsActivity.this.onlySelect || DialogsActivity.this.dialogsType != 0 || DialogsActivity.this.slidingView != null || recyclerView.getAdapter() != DialogsActivity.this.dialogsAdapter || !(viewHolder.itemView instanceof DialogCell)) {
                    return 0;
                }
                DialogCell dialogCell = (DialogCell) viewHolder.itemView;
                long dialogId = dialogCell.getDialogId();
                if (DialogsActivity.this.actionBar.isActionModeShowed()) {
                    TLRPC.Dialog dialog = DialogsActivity.this.getMessagesController().dialogs_dict.get(dialogId);
                    if (!DialogsActivity.this.allowMoving || dialog == null || !dialog.pinned || DialogObject.isFolderDialogId(dialogId)) {
                        return 0;
                    }
                    DialogsActivity.this.movingView = (DialogCell) viewHolder.itemView;
                    DialogsActivity.this.movingView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                    return makeMovementFlags(3, 0);
                }
                if (!DialogsActivity.this.allowSwipeDuringCurrentTouch || dialogId == DialogsActivity.this.getUserConfig().clientUserId || dialogId == 777000 || DialogsActivity.this.getMessagesController().isProxyDialog(dialogId, false)) {
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
            TLRPC.Dialog dialog = DialogsActivity.this.getMessagesController().dialogs_dict.get(dialogId);
            if (dialog == null || !dialog.pinned || DialogObject.isFolderDialogId(dialogId)) {
                return false;
            }
            int fromIndex = source.getAdapterPosition();
            int toIndex = target.getAdapterPosition();
            DialogsActivity.this.dialogsAdapter.notifyItemMoved(fromIndex, toIndex);
            DialogsActivity.this.updateDialogIndices();
            DialogsActivity.this.movingWas = true;
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
                DialogsActivity.this.slidingView = null;
                return;
            }
            DialogCell dialogCell = (DialogCell) viewHolder.itemView;
            long dialogId = dialogCell.getDialogId();
            if (!DialogObject.isFolderDialogId(dialogId)) {
                DialogsActivity.this.slidingView = dialogCell;
                final int position = viewHolder.getAdapterPosition();
                final int dialogIndex = DialogsActivity.this.dialogsAdapter.fixPosition(position);
                final int count = DialogsActivity.this.dialogsAdapter.getItemCount();
                Runnable finishRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$SwipeController$XJXnfx74wNdVQZ3-S0Mau6-Z7EU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onSwiped$1$DialogsActivity$SwipeController(dialogIndex, count, position);
                    }
                };
                DialogsActivity.this.setDialogsListFrozen(true);
                if (Utilities.random.nextInt(1000) == 1) {
                    if (DialogsActivity.this.pacmanAnimation == null) {
                        DialogsActivity dialogsActivity = DialogsActivity.this;
                        dialogsActivity.pacmanAnimation = new PacmanAnimation(dialogsActivity.listView);
                    }
                    DialogsActivity.this.pacmanAnimation.setFinishRunnable(finishRunnable);
                    DialogsActivity.this.pacmanAnimation.start();
                    return;
                }
                finishRunnable.run();
                return;
            }
            SharedConfig.toggleArchiveHidden();
            if (SharedConfig.archiveHidden) {
                DialogsActivity.this.waitingForScrollFinished = true;
                DialogsActivity.this.listView.smoothScrollBy(0, dialogCell.getMeasuredHeight() + dialogCell.getTop(), CubicBezierInterpolator.EASE_OUT);
                DialogsActivity.this.getUndoView().showWithAction(0L, 6, null, null);
            }
        }

        public /* synthetic */ void lambda$onSwiped$1$DialogsActivity$SwipeController(int dialogIndex, int count, int position) {
            RecyclerView.ViewHolder holder;
            final TLRPC.Dialog dialog = (TLRPC.Dialog) DialogsActivity.frozenDialogsList.remove(dialogIndex);
            final int pinnedNum = dialog.pinnedNum;
            DialogsActivity.this.slidingView = null;
            DialogsActivity.this.listView.invalidate();
            int added = DialogsActivity.this.getMessagesController().addDialogToFolder(dialog.id, DialogsActivity.this.folderId == 0 ? 1 : 0, -1, 0L);
            if (added == 2) {
                DialogsActivity.this.dialogsAdapter.notifyItemChanged(count - 1);
            }
            if (added != 2 || position != 0) {
                DialogsActivity.this.dialogsItemAnimator.prepareForRemove();
                DialogsActivity.access$3510(DialogsActivity.this);
                DialogsActivity.this.dialogsAdapter.notifyItemRemoved(position);
                DialogsActivity.this.dialogRemoveFinished = 2;
            }
            if (DialogsActivity.this.folderId == 0) {
                if (added == 2) {
                    DialogsActivity.this.dialogsItemAnimator.prepareForRemove();
                    if (position == 0) {
                        DialogsActivity.this.dialogChangeFinished = 2;
                        DialogsActivity.this.setDialogsListFrozen(true);
                        DialogsActivity.this.dialogsAdapter.notifyItemChanged(0);
                    } else {
                        DialogsActivity.access$3508(DialogsActivity.this);
                        DialogsActivity.this.dialogsAdapter.notifyItemInserted(0);
                        if (!SharedConfig.archiveHidden && DialogsActivity.this.layoutManager.findFirstVisibleItemPosition() == 0) {
                            DialogsActivity.this.listView.smoothScrollBy(0, -AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 78.0f : 72.0f));
                        }
                    }
                    ArrayList<TLRPC.Dialog> dialogs = DialogsActivity.getDialogsArray(DialogsActivity.this.currentAccount, DialogsActivity.this.dialogsType, DialogsActivity.this.folderId, false);
                    DialogsActivity.frozenDialogsList.add(0, dialogs.get(0));
                } else if (added == 1 && (holder = DialogsActivity.this.listView.findViewHolderForAdapterPosition(0)) != null && (holder.itemView instanceof DialogCell)) {
                    DialogCell cell = (DialogCell) holder.itemView;
                    cell.checkCurrentDialogIndex(true);
                    cell.animateArchiveAvatar();
                }
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                boolean hintShowed = preferences.getBoolean("archivehint_l", false) || SharedConfig.archiveHidden;
                if (!hintShowed) {
                    preferences.edit().putBoolean("archivehint_l", true).commit();
                }
                DialogsActivity.this.getUndoView().showWithAction(dialog.id, hintShowed ? 2 : 3, null, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$SwipeController$2XiLrdQOTsCcmnCJSjQgBcFBtUc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$0$DialogsActivity$SwipeController(dialog, pinnedNum);
                    }
                });
            }
            if (DialogsActivity.this.folderId != 0 && DialogsActivity.frozenDialogsList.isEmpty()) {
                DialogsActivity.this.listView.setEmptyView(null);
                DialogsActivity.this.progressView.setVisibility(4);
            }
        }

        public /* synthetic */ void lambda$null$0$DialogsActivity$SwipeController(TLRPC.Dialog dialog, int pinnedNum) {
            DialogsActivity.this.dialogsListFrozen = true;
            DialogsActivity.this.getMessagesController().addDialogToFolder(dialog.id, 0, pinnedNum, 0L);
            DialogsActivity.this.dialogsListFrozen = false;
            ArrayList<TLRPC.Dialog> dialogs = DialogsActivity.this.getMessagesController().getDialogs(0);
            int index = dialogs.indexOf(dialog);
            if (index >= 0) {
                ArrayList<TLRPC.Dialog> archivedDialogs = DialogsActivity.this.getMessagesController().getDialogs(1);
                if (!archivedDialogs.isEmpty() || index != 1) {
                    DialogsActivity.this.dialogInsertFinished = 2;
                    DialogsActivity.this.setDialogsListFrozen(true);
                    DialogsActivity.this.dialogsItemAnimator.prepareForRemove();
                    DialogsActivity.access$3508(DialogsActivity.this);
                    DialogsActivity.this.dialogsAdapter.notifyItemInserted(index);
                }
                if (archivedDialogs.isEmpty()) {
                    dialogs.remove(0);
                    if (index == 1) {
                        DialogsActivity.this.dialogChangeFinished = 2;
                        DialogsActivity.this.setDialogsListFrozen(true);
                        DialogsActivity.this.dialogsAdapter.notifyItemChanged(0);
                        return;
                    } else {
                        DialogsActivity.frozenDialogsList.remove(0);
                        DialogsActivity.this.dialogsItemAnimator.prepareForRemove();
                        DialogsActivity.access$3510(DialogsActivity.this);
                        DialogsActivity.this.dialogsAdapter.notifyItemRemoved(0);
                        return;
                    }
                }
                return;
            }
            DialogsActivity.this.dialogsAdapter.notifyDataSetChanged();
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onSelectedChanged(RecyclerView.ViewHolder viewHolder, int actionState) {
            if (viewHolder != null) {
                DialogsActivity.this.listView.hideSelector();
            }
            super.onSelectedChanged(viewHolder, actionState);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public long getAnimationDuration(RecyclerView recyclerView, int animationType, float animateDx, float animateDy) {
            if (animationType == 4) {
                return 200L;
            }
            if (animationType == 8 && DialogsActivity.this.movingView != null) {
                final View view = DialogsActivity.this.movingView;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$SwipeController$3kG4YIWIcEVokiQny2Vm8LtTXXA
                    @Override // java.lang.Runnable
                    public final void run() {
                        view.setBackgroundDrawable(null);
                    }
                }, DialogsActivity.this.dialogsItemAnimator.getMoveDuration());
                DialogsActivity.this.movingView = null;
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

    public DialogsActivity(Bundle args) {
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
        messageObject = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(final Context context) {
        Drawable drawable;
        this.searching = false;
        this.searchWas = false;
        this.pacmanAnimation = null;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$Xvx3H8VGG4HHUv4L7Kws3h0wiEI
            @Override // java.lang.Runnable
            public final void run() {
                Theme.createChatResources(context, false);
            }
        });
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
        ActionBarMenuItem item = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchExpand() {
                DialogsActivity.this.searching = true;
                if (DialogsActivity.this.switchItem != null) {
                    DialogsActivity.this.switchItem.setVisibility(8);
                }
                if (DialogsActivity.this.proxyItem != null && DialogsActivity.this.proxyItemVisisble) {
                    DialogsActivity.this.proxyItem.setVisibility(8);
                }
                if (DialogsActivity.this.listView != null) {
                    if (DialogsActivity.this.searchString != null) {
                        DialogsActivity.this.listView.setEmptyView(DialogsActivity.this.searchEmptyView);
                        DialogsActivity.this.progressView.setVisibility(8);
                    }
                    if (!DialogsActivity.this.onlySelect) {
                        DialogsActivity.this.floatingButtonContainer.setVisibility(8);
                    }
                }
                DialogsActivity.this.updatePasscodeButton();
                DialogsActivity.this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrGoBack", R.string.AccDescrGoBack));
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public boolean canCollapseSearch() {
                if (DialogsActivity.this.switchItem != null) {
                    DialogsActivity.this.switchItem.setVisibility(0);
                }
                if (DialogsActivity.this.proxyItem != null && DialogsActivity.this.proxyItemVisisble) {
                    DialogsActivity.this.proxyItem.setVisibility(0);
                }
                if (DialogsActivity.this.searchString != null) {
                    DialogsActivity.this.finishFragment();
                    return false;
                }
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchCollapse() {
                DialogsActivity.this.searching = false;
                DialogsActivity.this.searchWas = false;
                if (DialogsActivity.this.listView != null) {
                    DialogsActivity.this.listView.setEmptyView(DialogsActivity.this.folderId == 0 ? DialogsActivity.this.progressView : null);
                    DialogsActivity.this.searchEmptyView.setVisibility(8);
                    if (!DialogsActivity.this.onlySelect) {
                        DialogsActivity.this.floatingButtonContainer.setVisibility(0);
                        DialogsActivity.this.floatingHidden = true;
                        DialogsActivity.this.floatingButtonContainer.setTranslationY(AndroidUtilities.dp(100.0f));
                        DialogsActivity.this.hideFloatingButton(false);
                    }
                    if (DialogsActivity.this.listView.getAdapter() != DialogsActivity.this.dialogsAdapter) {
                        DialogsActivity.this.listView.setAdapter(DialogsActivity.this.dialogsAdapter);
                        DialogsActivity.this.dialogsAdapter.notifyDataSetChanged();
                    }
                }
                if (DialogsActivity.this.dialogsSearchAdapter != null) {
                    DialogsActivity.this.dialogsSearchAdapter.searchDialogs(null);
                }
                DialogsActivity.this.updatePasscodeButton();
                if (DialogsActivity.this.menuDrawable != null) {
                    DialogsActivity.this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrOpenMenu", R.string.AccDescrOpenMenu));
                }
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onTextChanged(EditText editText) {
                String text = editText.getText().toString();
                if (text.length() != 0 || (DialogsActivity.this.dialogsSearchAdapter != null && DialogsActivity.this.dialogsSearchAdapter.hasRecentRearch())) {
                    DialogsActivity.this.searchWas = true;
                    if (DialogsActivity.this.dialogsSearchAdapter != null && DialogsActivity.this.listView.getAdapter() != DialogsActivity.this.dialogsSearchAdapter) {
                        DialogsActivity.this.listView.setAdapter(DialogsActivity.this.dialogsSearchAdapter);
                        DialogsActivity.this.dialogsSearchAdapter.notifyDataSetChanged();
                    }
                    if (DialogsActivity.this.searchEmptyView != null && DialogsActivity.this.listView.getEmptyView() != DialogsActivity.this.searchEmptyView) {
                        DialogsActivity.this.progressView.setVisibility(8);
                        DialogsActivity.this.listView.setEmptyView(DialogsActivity.this.searchEmptyView);
                    }
                }
                if (DialogsActivity.this.dialogsSearchAdapter != null) {
                    DialogsActivity.this.dialogsSearchAdapter.searchDialogs(text);
                }
            }
        });
        item.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
        item.setContentDescription(LocaleController.getString("Search", R.string.Search));
        if (this.onlySelect) {
            this.actionBar.setBackButtonImage(R.id.ic_back);
            if (this.dialogsType == 3 && this.selectAlertString == null) {
                this.actionBar.setTitle(LocaleController.getString("ForwardTo", R.string.ForwardTo));
            } else {
                this.actionBar.setTitle(LocaleController.getString("SelectChat", R.string.SelectChat));
            }
        } else {
            if (this.searchString != null || this.folderId != 0) {
                ActionBar actionBar = this.actionBar;
                BackDrawable backDrawable = new BackDrawable(false);
                this.backDrawable = backDrawable;
                actionBar.setBackButtonDrawable(backDrawable);
            } else {
                ActionBar actionBar2 = this.actionBar;
                MenuDrawable menuDrawable = new MenuDrawable();
                this.menuDrawable = menuDrawable;
                actionBar2.setBackButtonDrawable(menuDrawable);
                this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrOpenMenu", R.string.AccDescrOpenMenu));
            }
            if (this.folderId != 0) {
                this.actionBar.setTitle(LocaleController.getString("ArchivedChats", R.string.ArchivedChats));
            } else if (BuildVars.DEBUG_VERSION) {
                this.actionBar.setTitle("हांवें Beta");
            } else {
                this.actionBar.setTitle(LocaleController.getString("AppName", R.string.AppName));
            }
            this.actionBar.setSupportsHolidayImage(true);
        }
        this.actionBar.setTitleActionRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$uJIzRSPXDj7uZ316t6cH_9dRm_g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createView$1$DialogsActivity();
            }
        });
        if (this.allowSwitchAccount && UserConfig.getActivatedAccountsCount() > 1) {
            this.switchItem = menu.addItemWithWidth(1, 0, AndroidUtilities.dp(56.0f));
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            avatarDrawable.setTextSize(AndroidUtilities.dp(12.0f));
            BackupImageView imageView = new BackupImageView(context);
            imageView.setRoundRadius(AndroidUtilities.dp(7.5f));
            this.switchItem.addView(imageView, LayoutHelper.createFrame(36, 36, 17));
            TLRPC.User user = getUserConfig().getCurrentUser();
            avatarDrawable.setInfo(user);
            imageView.getImageReceiver().setCurrentAccount(this.currentAccount);
            imageView.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
            int a = 0;
            for (int i = 3; a < i; i = 3) {
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
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) throws Exception {
                if (id == -1) {
                    if (DialogsActivity.this.actionBar.isActionModeShowed()) {
                        DialogsActivity.this.hideActionMode(true);
                        return;
                    }
                    if (!DialogsActivity.this.onlySelect && DialogsActivity.this.folderId == 0) {
                        if (DialogsActivity.this.parentLayout != null) {
                            DialogsActivity.this.parentLayout.getDrawerLayoutContainer().openDrawer(false);
                            return;
                        }
                        return;
                    }
                    DialogsActivity.this.finishFragment();
                    return;
                }
                if (id == 1) {
                    SharedConfig.appLocked = !SharedConfig.appLocked;
                    SharedConfig.saveConfig();
                    DialogsActivity.this.updatePasscodeButton();
                    return;
                }
                if (id == 2) {
                    DialogsActivity.this.presentFragment(new ProxyListActivity());
                    return;
                }
                if (id < 10 || id >= 13) {
                    if (id == 100 || id == 101 || id == 102 || id == 103 || id == 104 || id == 105) {
                        DialogsActivity.this.perfromSelectedDialogsAction(id, true);
                        return;
                    }
                    return;
                }
                if (DialogsActivity.this.getParentActivity() != null) {
                    DialogsActivityDelegate oldDelegate = DialogsActivity.this.delegate;
                    LaunchActivity launchActivity = (LaunchActivity) DialogsActivity.this.getParentActivity();
                    launchActivity.switchToAccount(id - 10, true);
                    DialogsActivity dialogsActivity = new DialogsActivity(DialogsActivity.this.arguments);
                    dialogsActivity.setDelegate(oldDelegate);
                    launchActivity.presentFragment(dialogsActivity, false, true);
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
        this.selectedDialogsCountTextView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$JM63bxTXAY4dpLFEJEMysf5taJ8
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return DialogsActivity.lambda$createView$2(view, motionEvent);
            }
        });
        this.pinItem = actionMode.addItemWithWidth(100, R.drawable.msg_pin, AndroidUtilities.dp(54.0f));
        this.muteItem = actionMode.addItemWithWidth(104, R.drawable.msg_archive, AndroidUtilities.dp(54.0f));
        this.deleteItem = actionMode.addItemWithWidth(102, R.drawable.msg_delete, AndroidUtilities.dp(54.0f), LocaleController.getString("Delete", R.string.Delete));
        ActionBarMenuItem otherItem = actionMode.addItemWithWidth(0, R.drawable.ic_ab_other, AndroidUtilities.dp(54.0f), LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
        this.archiveItem = otherItem.addSubItem(105, R.drawable.msg_archive, LocaleController.getString("Archive", R.string.Archive));
        this.readItem = otherItem.addSubItem(101, R.drawable.msg_markread, LocaleController.getString("MarkAsRead", R.string.MarkAsRead));
        this.clearItem = otherItem.addSubItem(103, R.drawable.msg_clear, LocaleController.getString("ClearHistory", R.string.ClearHistory));
        this.actionModeViews.add(this.pinItem);
        this.actionModeViews.add(this.muteItem);
        this.actionModeViews.add(this.deleteItem);
        this.actionModeViews.add(otherItem);
        ContentView contentView = new ContentView(context);
        this.fragmentView = contentView;
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.DialogsActivity.3
            private boolean firstLayout = true;
            private boolean ignoreLayout;

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, android.view.ViewGroup, android.view.View
            protected void dispatchDraw(Canvas canvas) {
                super.dispatchDraw(canvas);
                if (DialogsActivity.this.slidingView != null && DialogsActivity.this.pacmanAnimation != null) {
                    DialogsActivity.this.pacmanAnimation.draw(canvas, DialogsActivity.this.slidingView.getTop() + (DialogsActivity.this.slidingView.getMeasuredHeight() / 2));
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView
            public void setAdapter(RecyclerView.Adapter adapter) {
                super.setAdapter(adapter);
                this.firstLayout = true;
            }

            private void checkIfAdapterValid() {
                if (DialogsActivity.this.listView != null && DialogsActivity.this.dialogsAdapter != null && DialogsActivity.this.listView.getAdapter() == DialogsActivity.this.dialogsAdapter && DialogsActivity.this.lastItemsCount != DialogsActivity.this.dialogsAdapter.getItemCount()) {
                    this.ignoreLayout = true;
                    DialogsActivity.this.dialogsAdapter.notifyDataSetChanged();
                    this.ignoreLayout = false;
                }
            }

            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (DialogsActivity.this.searchEmptyView != null) {
                    DialogsActivity.this.searchEmptyView.setPadding(left, top, right, bottom);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.View
            protected void onMeasure(int widthSpec, int heightSpec) {
                if (this.firstLayout && DialogsActivity.this.getMessagesController().dialogsLoaded) {
                    if (DialogsActivity.this.hasHiddenArchive()) {
                        this.ignoreLayout = true;
                        DialogsActivity.this.layoutManager.scrollToPositionWithOffset(1, 0);
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
                if ((DialogsActivity.this.dialogRemoveFinished != 0 || DialogsActivity.this.dialogInsertFinished != 0 || DialogsActivity.this.dialogChangeFinished != 0) && !DialogsActivity.this.dialogsItemAnimator.isRunning()) {
                    DialogsActivity.this.onDialogAnimationFinished();
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
                if (DialogsActivity.this.waitingForScrollFinished || DialogsActivity.this.dialogRemoveFinished != 0 || DialogsActivity.this.dialogInsertFinished != 0 || DialogsActivity.this.dialogChangeFinished != 0) {
                    return false;
                }
                int action = e.getAction();
                if ((action == 1 || action == 3) && !DialogsActivity.this.itemTouchhelper.isIdle() && DialogsActivity.this.swipeController.swipingFolder) {
                    DialogsActivity.this.swipeController.swipeFolderBack = true;
                    if (DialogsActivity.this.itemTouchhelper.checkHorizontalSwipe(null, 4) != 0) {
                        SharedConfig.toggleArchiveHidden();
                        DialogsActivity.this.getUndoView().showWithAction(0L, 7, null, null);
                    }
                }
                boolean result = super.onTouchEvent(e);
                if ((action == 1 || action == 3) && DialogsActivity.this.allowScrollToHiddenView) {
                    int currentPosition = DialogsActivity.this.layoutManager.findFirstVisibleItemPosition();
                    if (currentPosition == 0) {
                        View view = DialogsActivity.this.layoutManager.findViewByPosition(currentPosition);
                        int height = (AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 78.0f : 72.0f) / 4) * 3;
                        int diff = view.getTop() + view.getMeasuredHeight();
                        if (view != null) {
                            if (diff < height) {
                                DialogsActivity.this.listView.smoothScrollBy(0, diff, CubicBezierInterpolator.EASE_OUT_QUINT);
                            } else {
                                DialogsActivity.this.listView.smoothScrollBy(0, view.getTop(), CubicBezierInterpolator.EASE_OUT_QUINT);
                            }
                        }
                    }
                    DialogsActivity.this.allowScrollToHiddenView = false;
                }
                return result;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent e) {
                if (DialogsActivity.this.waitingForScrollFinished || DialogsActivity.this.dialogRemoveFinished != 0 || DialogsActivity.this.dialogInsertFinished != 0 || DialogsActivity.this.dialogChangeFinished != 0) {
                    return false;
                }
                if (e.getAction() == 0) {
                    DialogsActivity.this.allowSwipeDuringCurrentTouch = !r0.actionBar.isActionModeShowed();
                    checkIfAdapterValid();
                }
                return super.onInterceptTouchEvent(e);
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setOverScrollMode(2);
        this.listView.addItemDecoration(TopBottomDecoration.getDefaultTopBottomCornerBg(10, 10, 7.5f));
        DialogsItemAnimator dialogsItemAnimator = new DialogsItemAnimator() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.4
            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onRemoveFinished(RecyclerView.ViewHolder item2) {
                if (DialogsActivity.this.dialogRemoveFinished == 2) {
                    DialogsActivity.this.dialogRemoveFinished = 1;
                }
            }

            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onAddFinished(RecyclerView.ViewHolder item2) {
                if (DialogsActivity.this.dialogInsertFinished == 2) {
                    DialogsActivity.this.dialogInsertFinished = 1;
                }
            }

            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onChangeFinished(RecyclerView.ViewHolder item2, boolean oldItem) {
                if (DialogsActivity.this.dialogChangeFinished == 2) {
                    DialogsActivity.this.dialogChangeFinished = 1;
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.DialogsItemAnimator
            protected void onAllAnimationsDone() {
                if (DialogsActivity.this.dialogRemoveFinished == 1 || DialogsActivity.this.dialogInsertFinished == 1 || DialogsActivity.this.dialogChangeFinished == 1) {
                    DialogsActivity.this.onDialogAnimationFinished();
                }
            }
        };
        this.dialogsItemAnimator = dialogsItemAnimator;
        this.listView.setItemAnimator(dialogsItemAnimator);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setInstantClick(true);
        this.listView.setTag(4);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context) { // from class: im.uwrkaxlmjj.ui.DialogsActivity.5
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public void smoothScrollToPosition(RecyclerView recyclerView2, RecyclerView.State state, int position) {
                if (DialogsActivity.this.hasHiddenArchive() && position == 1) {
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
                if (DialogsActivity.this.listView.getAdapter() == DialogsActivity.this.dialogsAdapter && DialogsActivity.this.dialogsType == 0 && !DialogsActivity.this.onlySelect && !DialogsActivity.this.allowScrollToHiddenView && DialogsActivity.this.folderId == 0 && dy < 0 && DialogsActivity.this.getMessagesController().hasHiddenArchive()) {
                    int currentPosition = DialogsActivity.this.layoutManager.findFirstVisibleItemPosition();
                    if (currentPosition == 0 && (view2 = DialogsActivity.this.layoutManager.findViewByPosition(currentPosition)) != null && view2.getBottom() <= AndroidUtilities.dp(1.0f)) {
                        currentPosition = 1;
                    }
                    if (currentPosition != 0 && currentPosition != -1 && (view = DialogsActivity.this.layoutManager.findViewByPosition(currentPosition)) != null) {
                        int dialogHeight = AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 78.0f : 72.0f) + 1;
                        int canScrollDy = (-view.getTop()) + ((currentPosition - 1) * dialogHeight);
                        int positiveDy = Math.abs(dy);
                        if (canScrollDy < positiveDy) {
                            DialogsActivity.this.totalConsumedAmount += Math.abs(dy);
                            dy = -canScrollDy;
                            if (DialogsActivity.this.startedScrollAtTop && DialogsActivity.this.totalConsumedAmount >= AndroidUtilities.dp(150.0f)) {
                                DialogsActivity.this.allowScrollToHiddenView = true;
                                try {
                                    DialogsActivity.this.listView.performHapticFeedback(3, 2);
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
        int lvMargin = AndroidUtilities.dp(10.0f);
        contentView.addView(this.listView, LayoutHelper.createFrame(-1, -1, lvMargin, 0, lvMargin, 0));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$5jmRsmCsLmNqPTP1qfqhk9zZYcQ
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i2) throws Exception {
                this.f$0.lambda$createView$3$DialogsActivity(view, i2);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.6
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public boolean onItemClick(View view, int position, float x, float y) throws Exception {
                TLRPC.Chat chat;
                if (DialogsActivity.this.getParentActivity() == null) {
                    return false;
                }
                if (!DialogsActivity.this.actionBar.isActionModeShowed() && !AndroidUtilities.isTablet() && !DialogsActivity.this.onlySelect && (view instanceof DialogCell)) {
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
                            if (message_id != 0 && (chat = DialogsActivity.this.getMessagesController().getChat(Integer.valueOf(-lower_part))) != null && chat.migrated_to != null) {
                                args.putInt("migrated_to", lower_part);
                                lower_part = -chat.migrated_to.channel_id;
                            }
                            args.putInt("chat_id", -lower_part);
                        }
                        if (message_id != 0) {
                            args.putInt("message_id", message_id);
                        }
                        if (DialogsActivity.this.searchString != null) {
                            if (DialogsActivity.this.getMessagesController().checkCanOpenChat(args, DialogsActivity.this)) {
                                DialogsActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                                DialogsActivity.this.presentFragmentAsPreview(new ChatActivity(args));
                            }
                        } else if (DialogsActivity.this.getMessagesController().checkCanOpenChat(args, DialogsActivity.this)) {
                            DialogsActivity.this.presentFragmentAsPreview(new ChatActivity(args));
                        }
                        return true;
                    }
                }
                RecyclerView.Adapter adapter = DialogsActivity.this.listView.getAdapter();
                if (adapter == DialogsActivity.this.dialogsSearchAdapter) {
                    DialogsActivity.this.dialogsSearchAdapter.getItem(position);
                    return false;
                }
                ArrayList<TLRPC.Dialog> dialogs = DialogsActivity.getDialogsArray(DialogsActivity.this.currentAccount, DialogsActivity.this.dialogsType, DialogsActivity.this.folderId, DialogsActivity.this.dialogsListFrozen);
                int position2 = DialogsActivity.this.dialogsAdapter.fixPosition(position);
                if (position2 < 0 || position2 >= dialogs.size()) {
                    return false;
                }
                TLRPC.Dialog dialog = dialogs.get(position2);
                if (DialogsActivity.this.onlySelect) {
                    if (DialogsActivity.this.dialogsType != 3 || DialogsActivity.this.selectAlertString != null || !DialogsActivity.this.validateSlowModeDialog(dialog.id)) {
                        return false;
                    }
                    DialogsActivity.this.dialogsAdapter.addOrRemoveSelectedDialog(dialog.id, view);
                    DialogsActivity.this.updateSelectedCount();
                } else {
                    if (dialog instanceof TLRPC.TL_dialogFolder) {
                        return false;
                    }
                    if (DialogsActivity.this.actionBar.isActionModeShowed() && dialog.pinned) {
                        return false;
                    }
                    DialogsActivity.this.showOrUpdateActionMode(dialog, view);
                }
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public void onLongClickRelease() {
                DialogsActivity.this.finishPreviewFragment();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public void onMove(float dx, float dy) {
                DialogsActivity.this.movePreviewFragment(dy);
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
        FrameLayout frameLayout = new FrameLayout(context);
        this.floatingButtonContainer = frameLayout;
        frameLayout.setVisibility((this.onlySelect || this.folderId != 0) ? 8 : 0);
        contentView.addView(this.floatingButtonContainer, LayoutHelper.createFrame((Build.VERSION.SDK_INT >= 21 ? 56 : 60) + 20, (Build.VERSION.SDK_INT >= 21 ? 56 : 60) + 14, (LocaleController.isRTL ? 3 : 5) | 80, LocaleController.isRTL ? 4.0f : 0.0f, 0.0f, LocaleController.isRTL ? 0.0f : 4.0f, 0.0f));
        this.floatingButtonContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$NpZreTtAj8ZHj_HtJKO0x5V1tPY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$4$DialogsActivity(view);
            }
        });
        ImageView imageView2 = new ImageView(context);
        this.floatingButton = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER);
        Drawable drawable2 = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_chats_actionBackground), Theme.getColor(Theme.key_chats_actionPressedBackground));
        if (Build.VERSION.SDK_INT >= 21) {
            drawable = drawable2;
        } else {
            Drawable shadowDrawable = context.getResources().getDrawable(R.drawable.floating_shadow).mutate();
            shadowDrawable.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
            CombinedDrawable combinedDrawable = new CombinedDrawable(shadowDrawable, drawable2, 0, 0);
            combinedDrawable.setIconSize(AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
            drawable = combinedDrawable;
        }
        this.floatingButton.setBackgroundDrawable(drawable);
        this.floatingButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chats_actionIcon), PorterDuff.Mode.MULTIPLY));
        this.floatingButton.setImageResource(R.drawable.floating_pencil);
        if (Build.VERSION.SDK_INT >= 21) {
            StateListAnimator animator = new StateListAnimator();
            animator.addState(new int[]{android.R.attr.state_pressed}, ObjectAnimator.ofFloat(this.floatingButton, (Property<ImageView, Float>) View.TRANSLATION_Z, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f)).setDuration(200L));
            animator.addState(new int[0], ObjectAnimator.ofFloat(this.floatingButton, (Property<ImageView, Float>) View.TRANSLATION_Z, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f)).setDuration(200L));
            this.floatingButton.setStateListAnimator(animator);
            this.floatingButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.7
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view, Outline outline) {
                    outline.setOval(0, 0, AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                }
            });
        }
        this.floatingButtonContainer.setContentDescription(LocaleController.getString("NewMessageTitle", R.string.NewMessageTitle));
        this.floatingButtonContainer.addView(this.floatingButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 56 : 60, Build.VERSION.SDK_INT >= 21 ? 56 : 60, 51, 10.0f, 0.0f, 10.0f, 0.0f));
        this.listView.setOnScrollListener(new AnonymousClass8());
        if (this.searchString == null) {
            this.dialogsAdapter = new DialogsAdapter(context, this.dialogsType, this.folderId, this.onlySelect) { // from class: im.uwrkaxlmjj.ui.DialogsActivity.9
                @Override // im.uwrkaxlmjj.ui.adapters.DialogsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
                public void notifyDataSetChanged() {
                    DialogsActivity.this.lastItemsCount = getItemCount();
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
        dialogsSearchAdapter.setDelegate(new AnonymousClass10());
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
            this.commentView.setDelegate(new ChatActivityEnterView.ChatActivityEnterViewDelegate() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.11
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
                    if (DialogsActivity.this.delegate != null) {
                        ArrayList<Long> selectedDialogs = DialogsActivity.this.dialogsAdapter.getSelectedDialogs();
                        if (!selectedDialogs.isEmpty()) {
                            DialogsActivity.this.delegate.didSelectDialogs(DialogsActivity.this, selectedDialogs, message, false);
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
            this.undoView[a2] = new UndoView(context) { // from class: im.uwrkaxlmjj.ui.DialogsActivity.12
                @Override // android.view.View
                public void setTranslationY(float translationY) {
                    super.setTranslationY(translationY);
                    if (this == DialogsActivity.this.undoView[0] && DialogsActivity.this.undoView[1].getVisibility() != 0) {
                        float diff = (getMeasuredHeight() + AndroidUtilities.dp(8.0f)) - translationY;
                        if (!DialogsActivity.this.floatingHidden) {
                            DialogsActivity.this.floatingButtonContainer.setTranslationY((DialogsActivity.this.floatingButtonContainer.getTranslationY() + DialogsActivity.this.additionalFloatingTranslation) - diff);
                        }
                        DialogsActivity.this.additionalFloatingTranslation = diff;
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.UndoView
                protected boolean canUndo() {
                    return !DialogsActivity.this.dialogsItemAnimator.isRunning();
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
    public /* synthetic */ void lambda$createView$1$DialogsActivity() {
        hideFloatingButton(false);
        this.listView.smoothScrollToPosition(hasHiddenArchive() ? 1 : 0);
    }

    static /* synthetic */ boolean lambda$createView$2(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$3$DialogsActivity(View view, int position) throws Exception {
        long dialog_id;
        TLRPC.Chat chat;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView == null || recyclerListView.getAdapter() == null || getParentActivity() == null) {
            return;
        }
        int message_id = 0;
        boolean isGlobalSearch = false;
        RecyclerView.Adapter adapter = this.listView.getAdapter();
        DialogsAdapter dialogsAdapter = this.dialogsAdapter;
        if (adapter != dialogsAdapter) {
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
                    MessageObject messageObject2 = (MessageObject) obj;
                    dialog_id = messageObject2.getDialogId();
                    message_id = messageObject2.getId();
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
            TLObject object = dialogsAdapter.getItem(position);
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
                    presentFragment(new DialogsActivity(args));
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
            DialogsAdapter dialogsAdapter2 = this.dialogsAdapter;
            if (dialogsAdapter2 != null) {
                this.openedDialogId = dialog_id;
                dialogsAdapter2.setOpenedDialogId(dialog_id);
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

    public /* synthetic */ void lambda$createView$4$DialogsActivity(View v) {
        Bundle args = new Bundle();
        args.putBoolean("destroyAfterSelect", true);
        presentFragment(new ContactsActivity(args));
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.DialogsActivity$8, reason: invalid class name */
    class AnonymousClass8 extends RecyclerView.OnScrollListener {
        AnonymousClass8() {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
            if (newState == 1) {
                if (DialogsActivity.this.searching && DialogsActivity.this.searchWas) {
                    AndroidUtilities.hideKeyboard(DialogsActivity.this.getParentActivity().getCurrentFocus());
                }
                DialogsActivity.this.scrollingManually = true;
            } else {
                DialogsActivity.this.scrollingManually = false;
            }
            if (DialogsActivity.this.waitingForScrollFinished && newState == 0) {
                DialogsActivity.this.waitingForScrollFinished = false;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            boolean goingDown;
            final boolean fromCache;
            int firstVisibleItem = DialogsActivity.this.layoutManager.findFirstVisibleItemPosition();
            int visibleItemCount = Math.abs(DialogsActivity.this.layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
            int totalItemCount = recyclerView.getAdapter().getItemCount();
            DialogsActivity.this.dialogsItemAnimator.onListScroll(-dy);
            if (DialogsActivity.this.searching && DialogsActivity.this.searchWas) {
                if (visibleItemCount > 0 && DialogsActivity.this.layoutManager.findLastVisibleItemPosition() == totalItemCount - 1 && !DialogsActivity.this.dialogsSearchAdapter.isMessagesSearchEndReached()) {
                    DialogsActivity.this.dialogsSearchAdapter.loadMoreSearchMessages();
                    return;
                }
                return;
            }
            if (visibleItemCount > 0 && DialogsActivity.this.layoutManager.findLastVisibleItemPosition() >= DialogsActivity.getDialogsArray(DialogsActivity.this.currentAccount, DialogsActivity.this.dialogsType, DialogsActivity.this.folderId, DialogsActivity.this.dialogsListFrozen).size() - 10 && ((!DialogsActivity.this.getMessagesController().isDialogsEndReached(DialogsActivity.this.folderId)) || !DialogsActivity.this.getMessagesController().isServerDialogsEndReached(DialogsActivity.this.folderId))) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$8$zFBNZGLGw0vxoOg9o8aiVEA6akc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onScrolled$0$DialogsActivity$8(fromCache);
                    }
                });
            }
            if (DialogsActivity.this.floatingButtonContainer.getVisibility() != 8) {
                View topChild = recyclerView.getChildAt(0);
                int firstViewTop = 0;
                if (topChild != null) {
                    firstViewTop = topChild.getTop();
                }
                boolean changed = true;
                if (DialogsActivity.this.prevPosition == firstVisibleItem) {
                    int topDelta = DialogsActivity.this.prevTop - firstViewTop;
                    goingDown = firstViewTop < DialogsActivity.this.prevTop;
                    changed = Math.abs(topDelta) > 1;
                } else {
                    goingDown = firstVisibleItem > DialogsActivity.this.prevPosition;
                }
                if (changed && DialogsActivity.this.scrollUpdated && (goingDown || (!goingDown && DialogsActivity.this.scrollingManually))) {
                    DialogsActivity.this.hideFloatingButton(goingDown);
                }
                DialogsActivity.this.prevPosition = firstVisibleItem;
                DialogsActivity.this.prevTop = firstViewTop;
                DialogsActivity.this.scrollUpdated = true;
            }
        }

        public /* synthetic */ void lambda$onScrolled$0$DialogsActivity$8(boolean fromCache) {
            DialogsActivity.this.getMessagesController().loadDialogs(DialogsActivity.this.folderId, -1, 100, fromCache);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.DialogsActivity$10, reason: invalid class name */
    class AnonymousClass10 implements DialogsSearchAdapter.DialogsSearchAdapterDelegate {
        AnonymousClass10() {
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void searchStateChanged(boolean search) {
            if (DialogsActivity.this.searching && DialogsActivity.this.searchWas && DialogsActivity.this.searchEmptyView != null) {
                if (search) {
                    DialogsActivity.this.searchEmptyView.showProgress();
                } else {
                    DialogsActivity.this.searchEmptyView.showTextView();
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void didPressedOnSubDialog(long did) {
            if (DialogsActivity.this.onlySelect) {
                if (DialogsActivity.this.validateSlowModeDialog(did)) {
                    if (DialogsActivity.this.dialogsAdapter.hasSelectedDialogs()) {
                        DialogsActivity.this.dialogsAdapter.addOrRemoveSelectedDialog(did, null);
                        DialogsActivity.this.updateSelectedCount();
                        DialogsActivity.this.closeSearch();
                        return;
                    }
                    DialogsActivity.this.didSelectResult(did, true, false);
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
            DialogsActivity.this.closeSearch();
            if (AndroidUtilities.isTablet() && DialogsActivity.this.dialogsAdapter != null) {
                DialogsActivity.this.dialogsAdapter.setOpenedDialogId(DialogsActivity.this.openedDialogId = did);
                DialogsActivity.this.updateVisibleRows(512);
            }
            if (DialogsActivity.this.searchString != null) {
                if (DialogsActivity.this.getMessagesController().checkCanOpenChat(args, DialogsActivity.this)) {
                    DialogsActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                    DialogsActivity.this.presentFragment(new ChatActivity(args));
                    return;
                }
                return;
            }
            if (DialogsActivity.this.getMessagesController().checkCanOpenChat(args, DialogsActivity.this)) {
                DialogsActivity.this.presentFragment(new ChatActivity(args));
            }
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void needRemoveHint(final int did) {
            TLRPC.User user;
            if (DialogsActivity.this.getParentActivity() == null || (user = DialogsActivity.this.getMessagesController().getUser(Integer.valueOf(did))) == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(DialogsActivity.this.getParentActivity());
            builder.setTitle(LocaleController.getString("ChatHintsDeleteAlertTitle", R.string.ChatHintsDeleteAlertTitle));
            builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("ChatHintsDeleteAlert", R.string.ChatHintsDeleteAlert, ContactsController.formatName(user.first_name, user.last_name))));
            builder.setPositiveButton(LocaleController.getString("StickersRemove", R.string.StickersRemove), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$10$0H9nMfloGYZPtSAGvmD6Vo_AYwU
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$needRemoveHint$0$DialogsActivity$10(did, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            DialogsActivity.this.showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }

        public /* synthetic */ void lambda$needRemoveHint$0$DialogsActivity$10(int did, DialogInterface dialogInterface, int i) {
            DialogsActivity.this.getMediaDataController().removePeer(did);
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void needClearList() {
            AlertDialog.Builder builder = new AlertDialog.Builder(DialogsActivity.this.getParentActivity());
            builder.setTitle(LocaleController.getString("ClearSearchAlertTitle", R.string.ClearSearchAlertTitle));
            builder.setMessage(LocaleController.getString("ClearSearchAlert", R.string.ClearSearchAlert));
            builder.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$10$0sUMFp8Hk-AlVepCsgn9Tsg3CWM
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$needClearList$1$DialogsActivity$10(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            DialogsActivity.this.showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }

        public /* synthetic */ void lambda$needClearList$1$DialogsActivity$10(DialogInterface dialogInterface, int i) {
            if (DialogsActivity.this.dialogsSearchAdapter.isRecentSearchDisplayed()) {
                DialogsActivity.this.dialogsSearchAdapter.clearRecentSearch();
            } else {
                DialogsActivity.this.dialogsSearchAdapter.clearRecentHashtags();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        DialogsAdapter dialogsAdapter = this.dialogsAdapter;
        if (dialogsAdapter != null && !this.dialogsListFrozen) {
            dialogsAdapter.notifyDataSetChanged();
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
        if (this.onlySelect || !XiaomiUtilities.isMIUI() || Build.VERSION.SDK_INT < 19 || XiaomiUtilities.isCustomPermissionGranted(XiaomiUtilities.OP_SHOW_WHEN_LOCKED) || getParentActivity() == null || MessagesController.getGlobalNotificationsSettings().getBoolean("askedAboutMiuiLockscreen", false)) {
            return;
        }
        showDialog(new AlertDialog.Builder(getParentActivity()).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("PermissionXiaomiLockscreen", R.string.PermissionXiaomiLockscreen)).setPositiveButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$gBMnqCP1th8EhVN3o8l2k0dQ-ts
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$onResume$5$DialogsActivity(dialogInterface, i);
            }
        }).setNegativeButton(LocaleController.getString("ContactsPermissionAlertNotNow", R.string.ContactsPermissionAlertNotNow), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$_ObBQEZ2IGHnwERv1SniGcH0E5A
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                MessagesController.getGlobalNotificationsSettings().edit().putBoolean("askedAboutMiuiLockscreen", true).commit();
            }
        }).create());
    }

    public /* synthetic */ void lambda$onResume$5$DialogsActivity(DialogInterface dialog, int which) {
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() throws Exception {
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
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$yms3m-XcLwFNx3tDzlZ7tN70jXk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onDialogAnimationFinished$7$DialogsActivity();
            }
        });
    }

    public /* synthetic */ void lambda$onDialogAnimationFinished$7$DialogsActivity() {
        if (this.folderId != 0 && frozenDialogsList.isEmpty()) {
            this.listView.setEmptyView(null);
            this.progressView.setVisibility(4);
            finishFragment();
        }
        setDialogsListFrozen(false);
        updateDialogIndices();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideActionMode(boolean animateCheck) throws Exception {
        this.actionBar.hideActionMode();
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
        updateVisibleRows((animateCheck ? 8192 : 0) | 196608);
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
    public void perfromSelectedDialogsAction(final int i, boolean z) throws Exception {
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
                getUndoView().showWithAction(0L, i3, null, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$ftr0xpO-rfGwM9rgqA5Tkp4Qc-4
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        this.f$0.lambda$perfromSelectedDialogsAction$8$DialogsActivity(arrayList2);
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
                builder.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$SIPS_SrZtkLJ6pzJ7BC7SXKnaTc
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i11) throws Exception {
                        this.f$0.lambda$perfromSelectedDialogsAction$9$DialogsActivity(i, dialogInterface, i11);
                    }
                });
            } else if (this.canClearCacheCount != 0) {
                builder.setTitle(LocaleController.formatString("ClearCacheFewChatsTitle", R.string.ClearCacheFewChatsTitle, LocaleController.formatPluralString("ChatsSelectedClearCache", size)));
                builder.setMessage(LocaleController.getString("AreYouSureClearHistoryCacheFewChats", R.string.AreYouSureClearHistoryCacheFewChats));
                builder.setPositiveButton(LocaleController.getString("ClearHistoryCache", R.string.ClearHistoryCache), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$kOs4sZEnu8RmppCQ38lOH9Xqirs
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i11) throws Exception {
                        this.f$0.lambda$perfromSelectedDialogsAction$10$DialogsActivity(i, dialogInterface, i11);
                    }
                });
            } else {
                builder.setTitle(LocaleController.formatString("ClearFewChatsTitle", R.string.ClearFewChatsTitle, LocaleController.formatPluralString("ChatsSelectedClear", size)));
                builder.setMessage(LocaleController.getString("AreYouSureClearHistoryFewChats", R.string.AreYouSureClearHistoryFewChats));
                builder.setPositiveButton(LocaleController.getString("ClearHistory", R.string.ClearHistory), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$D14-Hrjy3zaV8cu81OlGK-KacfU
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i11) throws Exception {
                        this.f$0.lambda$perfromSelectedDialogsAction$11$DialogsActivity(i, dialogInterface, i11);
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
                    boolean z4 = (tL_userEmpty == null || !tL_userEmpty.bot || MessagesController.isSupportUser(tL_userEmpty)) ? false : true;
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
                            AlertsCreator.createClearOrDeleteDialogAlert(this, i == 103, chat, tL_userEmpty, i12 == 0, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$rADnxTP-TNI3S-_EL4fv25Xsl3w
                                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
                                public final void run(boolean z5) throws Exception {
                                    this.f$0.lambda$perfromSelectedDialogsAction$13$DialogsActivity(i, chat2, jLongValue2, z5);
                                }
                            });
                            return;
                        }
                    } else if (i == 104) {
                        if (size == 1 && this.canMuteCount == 1) {
                            showDialog(AlertsCreator.createMuteAlert(getParentActivity(), jLongValue2), new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$QLR76ZmFBUFrj_bZObK8tVBnNDQ
                                @Override // android.content.DialogInterface.OnDismissListener
                                public final void onDismiss(DialogInterface dialogInterface) throws Exception {
                                    this.f$0.lambda$perfromSelectedDialogsAction$14$DialogsActivity(dialogInterface);
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
            hideFloatingButton(false);
            this.listView.smoothScrollToPosition(hasHiddenArchive() ? 1 : 0);
        }
        hideActionMode((i == 100 || i == 102) ? false : true);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$8$DialogsActivity(ArrayList copy) throws Exception {
        getMessagesController().addDialogToFolder(copy, this.folderId == 0 ? 0 : 1, -1, null, 0L);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$9$DialogsActivity(int action, DialogInterface dialog1, int which) throws Exception {
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

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$10$DialogsActivity(int action, DialogInterface dialog1, int which) throws Exception {
        perfromSelectedDialogsAction(action, false);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$11$DialogsActivity(int action, DialogInterface dialog1, int which) throws Exception {
        perfromSelectedDialogsAction(action, false);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$13$DialogsActivity(final int action, final TLRPC.Chat chat, final long selectedDialog, final boolean param) throws Exception {
        hideActionMode(false);
        if (action == 103 && ChatObject.isChannel(chat) && (!chat.megagroup || !TextUtils.isEmpty(chat.username))) {
            getMessagesController().deleteDialog(selectedDialog, 2, param);
            return;
        }
        if (action == 102 && this.folderId != 0 && getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false).size() == 1) {
            this.progressView.setVisibility(4);
        }
        getUndoView().showWithAction(selectedDialog, action != 103 ? 1 : 0, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$mq-3gsuHW0Gi5g_JNWXDSB1Cnp8
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$null$12$DialogsActivity(action, selectedDialog, param, chat);
            }
        });
    }

    public /* synthetic */ void lambda$null$12$DialogsActivity(int action, long selectedDialog, boolean param, TLRPC.Chat chat) throws Exception {
        if (action == 103) {
            getMessagesController().deleteDialog(selectedDialog, 1, param);
            return;
        }
        if (chat == null || ChatObject.isNotInChat(chat)) {
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

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$14$DialogsActivity(DialogInterface dialog12) throws Exception {
        hideActionMode(true);
    }

    private void updateCounters(boolean hide) {
        ArrayList<Long> selectedDialogs;
        TLRPC.User user;
        int canClearHistoryCount = 0;
        int canDeleteCount = 0;
        int canUnpinCount = 0;
        int canArchiveCount = 0;
        int canUnarchiveCount = 0;
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
                    canUnarchiveCount++;
                    selectedDialogs = selectedDialogs2;
                } else {
                    selectedDialogs = selectedDialogs2;
                    if (selectedDialog != getUserConfig().getClientUserId() && selectedDialog != 777000 && !getMessagesController().isProxyDialog(selectedDialog, false)) {
                        canArchiveCount++;
                    }
                }
                int lower_id = (int) selectedDialog;
                int canArchiveCount2 = canArchiveCount;
                int canUnarchiveCount2 = canUnarchiveCount;
                int high_id = (int) (selectedDialog >> 32);
                if (DialogObject.isChannel(dialog)) {
                    TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(-lower_id));
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
                    canUnarchiveCount = canUnarchiveCount2;
                } else {
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
                    canUnarchiveCount = canUnarchiveCount2;
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
        if (canUnarchiveCount != 0) {
            this.archiveItem.setTextAndIcon(LocaleController.getString("Unarchive", R.string.Unarchive), R.drawable.msg_unarchive);
            this.archiveItem.setVisibility(0);
        } else if (canArchiveCount == 0) {
            this.archiveItem.setVisibility(8);
        } else {
            this.archiveItem.setTextAndIcon(LocaleController.getString("Archive", R.string.Archive), R.drawable.msg_archive);
            this.archiveItem.setVisibility(0);
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
    public void showOrUpdateActionMode(TLRPC.Dialog dialog, View cell) throws Exception {
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

    protected RecyclerListView getListView() {
        return this.listView;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public UndoView getUndoView() {
        if (this.undoView[0].getVisibility() == 0) {
            UndoView[] undoViewArr = this.undoView;
            UndoView old = undoViewArr[0];
            undoViewArr[0] = undoViewArr[1];
            undoViewArr[1] = old;
            old.hide(true, 2);
            ContentView contentView = (ContentView) this.fragmentView;
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
                animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.13
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        DialogsActivity.this.commentView.setVisibility(8);
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
            animatorSet2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.14
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    DialogsActivity.this.commentView.setTag(2);
                    DialogsActivity.this.commentView.requestLayout();
                }
            });
            animatorSet2.start();
            this.commentView.setTag(1);
        }
        this.actionBar.setTitle(LocaleController.formatPluralString("Recipient", this.dialogsAdapter.getSelectedDialogs().size()));
    }

    private void askForPermissons(boolean alert) {
        FragmentActivity activity = getParentActivity();
        if (activity == null) {
            return;
        }
        ArrayList<String> permissons = new ArrayList<>();
        if (getUserConfig().syncContacts && this.askAboutContacts && activity.checkSelfPermission(PermissionUtils.LINKMAIN) != 0) {
            if (alert) {
                AlertDialog.Builder builder = AlertsCreator.createContactsPermissionDialog(activity, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$q4FeWPfVWwk5FdFvZYIKLJSP_xU
                    @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                    public final void run(int i) {
                        this.f$0.lambda$askForPermissons$15$DialogsActivity(i);
                    }
                });
                AlertDialog alertDialogCreate = builder.create();
                this.permissionDialog = alertDialogCreate;
                showDialog(alertDialogCreate);
                return;
            }
            permissons.add(PermissionUtils.LINKMAIN);
        }
        if (activity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
            permissons.add(im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE);
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

    public /* synthetic */ void lambda$askForPermissons$15$DialogsActivity(int param) {
        this.askAboutContacts = param != 0;
        MessagesController.getGlobalNotificationsSettings().edit().putBoolean("askAboutContacts", this.askAboutContacts).commit();
        askForPermissons(false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        super.onDialogDismiss(dialog);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        FrameLayout frameLayout;
        super.onConfigurationChanged(newConfig);
        if (!this.onlySelect && (frameLayout = this.floatingButtonContainer) != null) {
            frameLayout.getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() { // from class: im.uwrkaxlmjj.ui.DialogsActivity.15
                @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
                public void onGlobalLayout() {
                    DialogsActivity.this.floatingButtonContainer.setTranslationY(DialogsActivity.this.floatingHidden ? AndroidUtilities.dp(100.0f) : -DialogsActivity.this.additionalFloatingTranslation);
                    DialogsActivity.this.floatingButtonContainer.setClickable(!DialogsActivity.this.floatingHidden);
                    if (DialogsActivity.this.floatingButtonContainer != null) {
                        DialogsActivity.this.floatingButtonContainer.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                    }
                }
            });
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 1) {
            for (int a = 0; a < permissions.length; a++) {
                if (grantResults.length > a) {
                    String str = permissions[a];
                    byte b = -1;
                    int iHashCode = str.hashCode();
                    if (iHashCode != 1365911975) {
                        if (iHashCode == 1977429404 && str.equals(PermissionUtils.LINKMAIN)) {
                            b = 0;
                        }
                    } else if (str.equals("android.permission.WRITE_EXTERNAL_STORAGE")) {
                        b = 1;
                    }
                    if (b != 0) {
                        if (b == 1 && grantResults[a] == 0) {
                            ImageLoader.getInstance().checkMediaPaths();
                        }
                    } else if (grantResults[a] == 0) {
                        getContactsController().forceImportContacts();
                    } else {
                        SharedPreferences.Editor editorEdit = MessagesController.getGlobalNotificationsSettings().edit();
                        this.askAboutContacts = false;
                        editorEdit.putBoolean("askAboutContacts", false).commit();
                    }
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        DialogsAdapter dialogsAdapter;
        if (id == NotificationCenter.dialogsNeedReload) {
            if (this.dialogsListFrozen) {
                return;
            }
            DialogsAdapter dialogsAdapter2 = this.dialogsAdapter;
            if (dialogsAdapter2 != null) {
                if (!dialogsAdapter2.isDataSetChanged() && args.length <= 0) {
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
            if ((mask.intValue() & 4) != 0 && (dialogsAdapter = this.dialogsAdapter) != null) {
                dialogsAdapter.sortOnlineContacts(true);
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
                DialogsAdapter dialogsAdapter3 = this.dialogsAdapter;
                if (dialogsAdapter3 != null) {
                    dialogsAdapter3.notifyDataSetChanged();
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
                DialogsAdapter dialogsAdapter4 = this.dialogsAdapter;
                if (dialogsAdapter4 != null) {
                    dialogsAdapter4.setOpenedDialogId(this.openedDialogId);
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
                Runnable deleteRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$LOz99AKtXbi4Fg4EGpHTsY82dpw
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        this.f$0.lambda$didReceivedNotification$16$DialogsActivity(chat, dialogId, revoke);
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

    public /* synthetic */ void lambda$didReceivedNotification$16$DialogsActivity(TLRPC.Chat chat, long dialogId, boolean revoke) throws Exception {
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
        MessageObject messageObject2;
        ArrayList<TLRPC.Dialog> arrayList;
        if (frozen && (arrayList = frozenDialogsList) != null) {
            return arrayList;
        }
        ArrayList<TLRPC.Dialog> dialogs = new ArrayList<>();
        MessagesController messagesController = AccountInstance.getInstance(currentAccount).getMessagesController();
        long j = 0;
        if (dialogsType == 0) {
            dialogs = messagesController.getDialogs(folderId);
        } else if (dialogsType != 1) {
            if (dialogsType == 2) {
                dialogs = messagesController.dialogsCanAddUsers;
            } else if (dialogsType != 3) {
                if (dialogsType != 4) {
                    if (dialogsType != 5) {
                        if (dialogsType != 6) {
                            if (dialogsType != 9) {
                                if (dialogsType != 7) {
                                    if (dialogsType == 8) {
                                        ArrayList<TLRPC.Dialog> dialogsTemp = messagesController.getDialogs(folderId);
                                        for (TLRPC.Dialog dialog : dialogsTemp) {
                                            if (dialog.unread_mentions_count != 0 || dialog.unread_count != 0) {
                                                dialogs.add(dialog);
                                            }
                                        }
                                    }
                                } else {
                                    for (TLRPC.Dialog dialog2 : messagesController.dialogsForward) {
                                        long dialogId = dialog2.id;
                                        if (dialogId != 0) {
                                            int lower_id = (int) dialogId;
                                            if (lower_id != 0) {
                                                dialogs.add(dialog2);
                                            }
                                        }
                                    }
                                }
                            } else {
                                dialogs = messagesController.dialogsUnreadOnly;
                            }
                        } else {
                            dialogs = messagesController.dialogsGroupsOnly;
                        }
                    } else {
                        dialogs = messagesController.dialogsChannelsOnly;
                    }
                } else {
                    dialogs = messagesController.dialogsUsersOnly;
                }
            } else {
                dialogs = messagesController.dialogsForward;
            }
        } else {
            dialogs = messagesController.dialogsServerOnly;
        }
        MessageObject messageObject3 = messageObject;
        boolean hasLink = RegexUtils.hasLink(messageObject3 != null ? messageObject3.messageText.toString() : "") && dialogsType == 3;
        ArrayList<TLRPC.Dialog> result = new ArrayList<>();
        for (TLRPC.Dialog d : dialogs) {
            if (d != null) {
                long dialogId2 = d.id;
                if (dialogId2 < j) {
                    TLRPC.Chat chat = MessagesController.getInstance(UserConfig.selectedAccount).getChat(Integer.valueOf(-((int) dialogId2)));
                    if (ChatObject.canSendMessages(chat)) {
                        if (!ChatObject.canSendEmbed(chat)) {
                            if (hasLink || !((messageObject2 = messageObject) == null || TextUtils.isEmpty(messageObject2.messageText) || !messageObject.messageText.toString().startsWith("@"))) {
                                j = 0;
                            } else {
                                MessageObject messageObject4 = messageObject;
                                if (messageObject4 != null && messageObject4.type == 103) {
                                    j = 0;
                                }
                            }
                        }
                    }
                }
                result.add(d);
            }
            j = 0;
        }
        if (result.size() >= 1) {
            result.remove(0);
        }
        return result;
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
    public void hideFloatingButton(boolean hide) {
        if (this.floatingHidden == hide) {
            return;
        }
        this.floatingHidden = hide;
        AnimatorSet animatorSet = new AnimatorSet();
        Animator[] animatorArr = new Animator[1];
        FrameLayout frameLayout = this.floatingButtonContainer;
        Property property = View.TRANSLATION_Y;
        float[] fArr = new float[1];
        fArr[0] = this.floatingHidden ? AndroidUtilities.dp(100.0f) : -this.additionalFloatingTranslation;
        animatorArr[0] = ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr);
        animatorSet.playTogether(animatorArr);
        animatorSet.setDuration(300L);
        animatorSet.setInterpolator(this.floatingInterpolator);
        this.floatingButtonContainer.setClickable(!hide);
        animatorSet.start();
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
            builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$xXT01TqUUmWBItz6xH4Ietuv1fk
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$didSelectResult$17$DialogsActivity(dialog_id, dialogInterface, i);
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

    public /* synthetic */ void lambda$didSelectResult$17$DialogsActivity(long dialog_id, DialogInterface dialogInterface, int i) {
        didSelectResult(dialog_id, false, false);
    }

    public static void setTempForwardMessageObject(MessageObject messageObject2) {
        messageObject = messageObject2;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$DialogsActivity$KirXIROk0hOrB6bO40LQNTbgL84
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$18$DialogsActivity();
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
        arrayList.add(new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chats_actionIcon));
        arrayList.add(new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chats_actionBackground));
        arrayList.add(new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_chats_actionPressedBackground));
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
        DialogsAdapter dialogsAdapter = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(dialogsAdapter != null ? dialogsAdapter.getArchiveHintCellPager() : null, 0, new Class[]{ArchiveHintInnerCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_nameMessage_threeLines));
        DialogsAdapter dialogsAdapter2 = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(dialogsAdapter2 != null ? dialogsAdapter2.getArchiveHintCellPager() : null, 0, new Class[]{ArchiveHintInnerCell.class}, new String[]{"imageView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_unreadCounter));
        DialogsAdapter dialogsAdapter3 = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(dialogsAdapter3 != null ? dialogsAdapter3.getArchiveHintCellPager() : null, 0, new Class[]{ArchiveHintInnerCell.class}, new String[]{"headerTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_nameMessage_threeLines));
        DialogsAdapter dialogsAdapter4 = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(dialogsAdapter4 != null ? dialogsAdapter4.getArchiveHintCellPager() : null, 0, new Class[]{ArchiveHintInnerCell.class}, new String[]{"messageTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_message));
        DialogsAdapter dialogsAdapter5 = this.dialogsAdapter;
        arrayList.add(new ThemeDescription(dialogsAdapter5 != null ? dialogsAdapter5.getArchiveHintCellPager() : null, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefaultArchived));
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

    public /* synthetic */ void lambda$getThemeDescriptions$18$DialogsActivity() {
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
}
