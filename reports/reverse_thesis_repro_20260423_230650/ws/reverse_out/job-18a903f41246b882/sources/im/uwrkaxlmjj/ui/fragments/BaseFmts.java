package im.uwrkaxlmjj.ui.fragments;

import android.animation.ObjectAnimator;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import butterknife.ButterKnife;
import butterknife.Unbinder;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocationController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarLayout;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.constants.Constants;
import java.util.Objects;

/* JADX INFO: loaded from: classes5.dex */
public abstract class BaseFmts extends Fragment implements Constants {
    protected ActionBar actionBar;
    protected Bundle arguments;
    protected int classGuid;
    protected Context context;
    protected int currentAccount;
    protected Drawable defaultActionBarBackgroundDrawable;
    protected View fragmentView;
    protected boolean hasOwnBackground;
    protected boolean inPreviewMode;
    protected boolean isPaused;
    private boolean mIsFirst;
    private boolean mIsPrepared;
    private boolean mIsVisible;
    protected ActionBarLayout parentLayout;
    private Unbinder unbinder;
    protected Dialog visibleDialog;

    public BaseFmts() {
        this(null);
    }

    public BaseFmts(Bundle args) {
        this.currentAccount = UserConfig.selectedAccount;
        this.hasOwnBackground = false;
        this.isPaused = true;
        this.mIsFirst = true;
        this.classGuid = ConnectionsManager.generateClassGuid();
        this.arguments = args;
        this.defaultActionBarBackgroundDrawable = new ColorDrawable(Theme.getColor(Theme.key_actionBarDefault));
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        this.context = context;
    }

    @Override // androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        this.mIsPrepared = true;
        this.parentLayout = getParentLayout();
        afterPrepared();
        checkToLazyLoad();
    }

    @Override // androidx.fragment.app.Fragment
    public void setUserVisibleHint(boolean isVisibleToUser) {
        super.setUserVisibleHint(isVisibleToUser);
        if (getUserVisibleHint()) {
            this.mIsVisible = true;
        } else {
            this.mIsVisible = false;
        }
        checkToLazyLoad();
    }

    public ActionBarLayout getActionBarLayout() {
        return this.parentLayout;
    }

    public ActionBar getActionBar() {
        return this.actionBar;
    }

    ActionBar createActionBar() {
        ActionBar actionBar = new ActionBar(this.context);
        this.actionBar = actionBar;
        actionBar.setBackground(this.defaultActionBarBackgroundDrawable);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultSelector), false);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarActionModeDefaultSelector), true);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_actionBarDefaultIcon), false);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon), true);
        if (this.inPreviewMode) {
            this.actionBar.setOccupyStatusBar(false);
        }
        ActionBarLayout actionBarLayout = this.parentLayout;
        if (actionBarLayout != null) {
            actionBarLayout.setBackgroundColor(Theme.getColor(Theme.key_actionBarDefault));
        }
        return this.actionBar;
    }

    private void checkToLazyLoad() {
        if (this.mIsPrepared) {
            if (this.mIsVisible) {
                if (this.mIsFirst) {
                    this.mIsFirst = false;
                    lazyLoadData();
                    return;
                } else {
                    onVisible();
                    return;
                }
            }
            onInvisible();
        }
    }

    protected void afterPrepared() {
    }

    protected void onVisible() {
    }

    protected void onInvisible() {
    }

    protected void lazyLoadData() {
    }

    public void onResumeForBaseFragment() {
        this.isPaused = false;
    }

    public void onPauseForBaseFragment() {
        this.isPaused = true;
    }

    public boolean isFirstTimeInThisPage() {
        return this.mIsFirst;
    }

    public void reSetFirstLoad(boolean mIsFirst) {
        this.mIsFirst = mIsFirst;
    }

    public boolean isFragmentVisible() {
        return this.mIsVisible;
    }

    public boolean resetActionBar() {
        ActionBar actionBar = this.actionBar;
        if (actionBar != null) {
            if (actionBar.isActionModeShowed()) {
                this.actionBar.hideActionMode();
            }
            if (this.actionBar.isSearchFieldVisible()) {
                this.actionBar.closeSearchField();
                return false;
            }
            return false;
        }
        return true;
    }

    public void hideTitle(View rootView) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(rootView, "translationY", 0.0f, -ActionBar.getCurrentActionBarHeight());
        animator.setDuration(300L);
        animator.start();
        this.actionBar.setVisibility(4);
    }

    public void showTitle(View rootView) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(rootView, "translationY", -ActionBar.getCurrentActionBarHeight(), 0.0f);
        animator.start();
        this.actionBar.setVisibility(0);
    }

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        return super.onCreateView(inflater, container, savedInstanceState);
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        this.mIsPrepared = false;
        this.mIsVisible = false;
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        Unbinder unbinder = this.unbinder;
        if (unbinder != null) {
            try {
                unbinder.unbind();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
        super.onDestroy();
        this.mIsPrepared = false;
    }

    public Activity getParentActivity() {
        return getActivity();
    }

    public boolean presentFragment(BaseFragment fragment) {
        ActionBarLayout parentLayout = getParentLayout();
        this.parentLayout = parentLayout;
        return parentLayout != null && parentLayout.presentFragment(fragment);
    }

    public boolean presentFragment(BaseFragment fragment, boolean removeLast) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        return actionBarLayout != null && actionBarLayout.presentFragment(fragment, removeLast);
    }

    public boolean presentFragment(BaseFragment fragment, boolean removeLast, boolean forceWithoutAnimation) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        return actionBarLayout != null && actionBarLayout.presentFragment(fragment, removeLast, forceWithoutAnimation, true, false);
    }

    public BaseFragment getCurrentFragment() {
        return getParentLayout().getCurrentFragment();
    }

    private ActionBarLayout getParentLayout() {
        return ((LaunchActivity) Objects.requireNonNull(getActivity())).getActionBarLayout();
    }

    public Dialog showDialog(Dialog dialog) {
        return showDialog(dialog, false, null);
    }

    public Dialog showDialog(Dialog dialog, DialogInterface.OnDismissListener onDismissListener) {
        return showDialog(dialog, false, onDismissListener);
    }

    public Dialog showDialog(Dialog dialog, boolean allowInTransition, final DialogInterface.OnDismissListener onDismissListener) {
        ActionBarLayout actionBarLayout;
        if (dialog == null || (actionBarLayout = this.parentLayout) == null || (!allowInTransition && actionBarLayout.checkTransitionAnimation())) {
            return null;
        }
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            this.visibleDialog = dialog;
            dialog.setCanceledOnTouchOutside(true);
            this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$BaseFmts$x3RMbQtWj7LBYlsaDTWAsn7A9aY
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$showDialog$0$BaseFmts(onDismissListener, dialogInterface);
                }
            });
            this.visibleDialog.show();
            return this.visibleDialog;
        } catch (Exception e2) {
            FileLog.e(e2);
            return null;
        }
    }

    public /* synthetic */ void lambda$showDialog$0$BaseFmts(DialogInterface.OnDismissListener onDismissListener, DialogInterface dialog1) {
        if (onDismissListener != null) {
            onDismissListener.onDismiss(dialog1);
        }
        onDialogDismiss(this.visibleDialog);
        this.visibleDialog = null;
    }

    public void dismissCurrentDialog() {
        Dialog dialog = this.visibleDialog;
        if (dialog == null) {
            return;
        }
        try {
            dialog.dismiss();
            this.visibleDialog = null;
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    protected void onDialogDismiss(Dialog dialog) {
    }

    public int getClassGuid() {
        return this.classGuid;
    }

    public Dialog getVisibleDialog() {
        return this.visibleDialog;
    }

    public AccountInstance getAccountInstance() {
        return AccountInstance.getInstance(this.currentAccount);
    }

    public UserConfig getUserConfig() {
        return getAccountInstance().getUserConfig();
    }

    public MessagesController getMessagesController() {
        return getAccountInstance().getMessagesController();
    }

    protected ContactsController getContactsController() {
        return getAccountInstance().getContactsController();
    }

    protected MediaDataController getMediaDataController() {
        return getAccountInstance().getMediaDataController();
    }

    public ConnectionsManager getConnectionsManager() {
        return getAccountInstance().getConnectionsManager();
    }

    protected LocationController getLocationController() {
        return getAccountInstance().getLocationController();
    }

    protected NotificationsController getNotificationsController() {
        return getAccountInstance().getNotificationsController();
    }

    protected MessagesStorage getMessagesStorage() {
        return getAccountInstance().getMessagesStorage();
    }

    protected SendMessagesHelper getSendMessagesHelper() {
        return getAccountInstance().getSendMessagesHelper();
    }

    public boolean onBackPressed() {
        return false;
    }

    protected void useButterKnife() {
        View view = this.fragmentView;
        if (view != null) {
            this.unbinder = ButterKnife.bind(this, view);
        }
    }
}
