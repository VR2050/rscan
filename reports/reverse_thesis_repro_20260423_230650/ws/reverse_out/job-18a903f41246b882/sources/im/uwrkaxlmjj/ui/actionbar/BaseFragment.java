package im.uwrkaxlmjj.ui.actionbar;

import android.animation.AnimatorSet;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.accessibility.AccessibilityManager;
import androidx.fragment.app.FragmentActivity;
import butterknife.ButterKnife;
import butterknife.Unbinder;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocationController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SecretChatHelper;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.status.StatusBarUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.ui.wallet.WalletController;

/* JADX INFO: loaded from: classes5.dex */
public class BaseFragment {
    protected ActionBar actionBar;
    protected Bundle arguments;
    protected int classGuid;
    protected int currentAccount;
    protected Drawable defaultActionBarBackgroundDrawable;
    private boolean finishing;
    protected View fragmentView;
    protected Drawable gameActionBarBackgroundDrawable;
    protected boolean hasOwnBackground;
    protected boolean inPreviewMode;
    private boolean isFinished;
    protected boolean isPaused;
    protected ActionBarLayout parentLayout;
    protected boolean swipeBackEnabled;
    private Unbinder unbinder;
    protected Dialog visibleDialog;

    public BaseFragment() {
        this(null);
    }

    public BaseFragment(Bundle args) {
        this.currentAccount = UserConfig.selectedAccount;
        this.swipeBackEnabled = true;
        this.hasOwnBackground = false;
        this.isPaused = true;
        this.arguments = args;
        this.classGuid = ConnectionsManager.generateClassGuid();
        this.isFinished = false;
        this.finishing = false;
    }

    public void setCurrentAccount(int account) {
        if (this.fragmentView != null) {
            throw new IllegalStateException("trying to set current account when fragment UI already created");
        }
        this.currentAccount = account;
    }

    public ActionBarLayout getParentLayout() {
        return this.parentLayout;
    }

    public ActionBar getActionBar() {
        return this.actionBar;
    }

    public View getFragmentView() {
        return this.fragmentView;
    }

    public View createView(Context context) {
        return null;
    }

    public Bundle getArguments() {
        return this.arguments;
    }

    public int getCurrentAccount() {
        return this.currentAccount;
    }

    public int getClassGuid() {
        return this.classGuid;
    }

    protected void setInPreviewMode(boolean value) {
        this.inPreviewMode = value;
        ActionBar actionBar = this.actionBar;
        if (actionBar != null) {
            if (value) {
                actionBar.setOccupyStatusBar(false);
            } else {
                actionBar.setOccupyStatusBar(Build.VERSION.SDK_INT >= 21);
            }
        }
    }

    protected void clearViews() {
        View view = this.fragmentView;
        if (view != null) {
            ViewGroup parent = (ViewGroup) view.getParent();
            if (parent != null) {
                try {
                    onRemoveFromParent();
                    parent.removeView(this.fragmentView);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
            this.fragmentView = null;
        }
        ActionBar actionBar = this.actionBar;
        if (actionBar != null) {
            ViewGroup parent2 = (ViewGroup) actionBar.getParent();
            if (parent2 != null) {
                try {
                    parent2.removeView(this.actionBar);
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
            this.actionBar = null;
        }
        this.parentLayout = null;
    }

    protected void onRemoveFromParent() {
    }

    public void setParentFragment(BaseFragment fragment) {
        setParentLayout(fragment.parentLayout);
        this.fragmentView = createView(this.parentLayout.getContext());
    }

    protected void setParentLayout(ActionBarLayout layout) {
        ViewGroup parent;
        if (this.parentLayout != layout) {
            this.parentLayout = layout;
            View view = this.fragmentView;
            if (view != null) {
                ViewGroup parent2 = (ViewGroup) view.getParent();
                if (parent2 != null) {
                    try {
                        onRemoveFromParent();
                        parent2.removeView(this.fragmentView);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
                ActionBarLayout actionBarLayout = this.parentLayout;
                if (actionBarLayout != null && actionBarLayout.getContext() != this.fragmentView.getContext()) {
                    this.fragmentView = null;
                }
            }
            if (this.actionBar != null) {
                ActionBarLayout actionBarLayout2 = this.parentLayout;
                boolean differentParent = (actionBarLayout2 == null || actionBarLayout2.getContext() == this.actionBar.getContext()) ? false : true;
                if ((this.actionBar.getAddToContainer() || differentParent) && (parent = (ViewGroup) this.actionBar.getParent()) != null) {
                    try {
                        parent.removeView(this.actionBar);
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                }
                if (differentParent) {
                    this.actionBar = null;
                }
            }
            ActionBarLayout actionBarLayout3 = this.parentLayout;
            if (actionBarLayout3 != null && this.actionBar == null) {
                ActionBar actionBarCreateActionBar = createActionBar(actionBarLayout3.getContext());
                this.actionBar = actionBarCreateActionBar;
                actionBarCreateActionBar.parentFragment = this;
            }
        }
        this.isFinished = false;
        this.finishing = false;
    }

    protected void createActionBarBackgroundDrawable() {
        this.defaultActionBarBackgroundDrawable = Theme.createRoundRectDrawable(0.0f, Theme.getColor(Theme.key_actionBarDefault));
        this.gameActionBarBackgroundDrawable = new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, new int[]{Color.parseColor("#FFFE6869"), Color.parseColor("#FFFE856B")});
    }

    protected ActionBar createActionBar(Context context) {
        createActionBarBackgroundDrawable();
        ActionBar actionBar = new ActionBar(context);
        actionBar.setBackground(this.defaultActionBarBackgroundDrawable);
        actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultSelector), false);
        actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarActionModeDefaultSelector), true);
        actionBar.setItemsColor(Theme.getColor(Theme.key_actionBarDefaultIcon), false);
        actionBar.setItemsColor(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon), true);
        if (this.inPreviewMode) {
            actionBar.setOccupyStatusBar(false);
        }
        ActionBarLayout actionBarLayout = this.parentLayout;
        if (actionBarLayout != null) {
            actionBarLayout.setBackgroundColor(Theme.getColor(Theme.key_actionBarDefault));
        }
        return actionBar;
    }

    public void movePreviewFragment(float dy) {
        this.parentLayout.movePreviewFragment(dy);
    }

    public void finishPreviewFragment() {
        this.parentLayout.finishPreviewFragment();
    }

    public void finishFragment() {
        finishFragment(true);
    }

    public void finishFragment(boolean animated) {
        ActionBarLayout actionBarLayout;
        if (this.isFinished || (actionBarLayout = this.parentLayout) == null) {
            return;
        }
        this.finishing = true;
        actionBarLayout.closeLastFragment(animated);
    }

    public void finishFragmentFromUp(boolean animated) {
        ActionBarLayout actionBarLayout;
        if (this.isFinished || (actionBarLayout = this.parentLayout) == null) {
            return;
        }
        this.finishing = true;
        actionBarLayout.closeLastFragmentFromUp(animated);
    }

    public void removeSelfFromStack() {
        ActionBarLayout actionBarLayout;
        if (this.isFinished || (actionBarLayout = this.parentLayout) == null) {
            return;
        }
        this.finishing = true;
        actionBarLayout.removeFragmentFromStack(this);
    }

    public boolean isFinishing() {
        return this.finishing;
    }

    public boolean onFragmentCreate() {
        return true;
    }

    public void onFragmentDestroy() {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequestsForGuid(this.classGuid);
        this.isFinished = true;
        ActionBar actionBar = this.actionBar;
        if (actionBar != null) {
            actionBar.setEnabled(false);
        }
        Unbinder unbinder = this.unbinder;
        if (unbinder != null) {
            try {
                unbinder.unbind();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public boolean needDelayOpenAnimation() {
        return false;
    }

    public void onResume() {
        this.isPaused = false;
        setStatusBarTheme();
    }

    protected void setStatusBarTheme() {
        if (Theme.getCurrentTheme() != null && Theme.getCurrentTheme().isDark()) {
            StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), false);
        } else {
            StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), true);
            setNavigationBarColor(Theme.getColor(Theme.key_bottomBarBackground));
        }
    }

    public void onPause() {
        ActionBar actionBar = this.actionBar;
        if (actionBar != null) {
            actionBar.onPause();
        }
        this.isPaused = true;
        try {
            if (this.visibleDialog != null && this.visibleDialog.isShowing() && dismissDialogOnPause(this.visibleDialog)) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public BaseFragment getFragmentForAlert(int offset) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        if (actionBarLayout == null || actionBarLayout.fragmentsStack.size() <= offset + 1) {
            return this;
        }
        return this.parentLayout.fragmentsStack.get((this.parentLayout.fragmentsStack.size() - 2) - offset);
    }

    public void onConfigurationChanged(Configuration newConfig) {
    }

    public boolean onBackPressed() {
        return true;
    }

    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
    }

    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
    }

    public void setArguments(Bundle arguments) {
        this.arguments = arguments;
    }

    public void saveSelfArgs(Bundle args) {
    }

    public void restoreSelfArgs(Bundle args) {
    }

    public boolean presentFragmentAsPreview(BaseFragment fragment) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        return actionBarLayout != null && actionBarLayout.presentFragmentAsPreview(fragment);
    }

    public boolean presentFragment(BaseFragment fragment) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        return actionBarLayout != null && actionBarLayout.presentFragment(fragment);
    }

    public boolean presentFragment(BaseFragment fragment, boolean removeLast) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        return actionBarLayout != null && actionBarLayout.presentFragment(fragment, removeLast);
    }

    public boolean presentFragment(BaseFragment fragment, boolean removeLast, boolean forceWithoutAnimation) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        return actionBarLayout != null && actionBarLayout.presentFragment(fragment, removeLast, forceWithoutAnimation, true, false);
    }

    public boolean presentFragmentFromBottom(BaseFragment fragment, boolean removeLast, boolean forceWithoutAnimation) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        return actionBarLayout != null && actionBarLayout.presentFragmentFromBottom(fragment, removeLast, forceWithoutAnimation, true, false);
    }

    public FragmentActivity getParentActivity() {
        ActionBarLayout actionBarLayout = this.parentLayout;
        if (actionBarLayout != null) {
            return actionBarLayout.parentActivity;
        }
        return null;
    }

    protected void setParentActivityTitle(CharSequence title) {
        Activity activity = getParentActivity();
        if (activity != null) {
            activity.setTitle(title);
        }
    }

    public void startActivityForResult(Intent intent, int requestCode) {
        ActionBarLayout actionBarLayout = this.parentLayout;
        if (actionBarLayout != null) {
            actionBarLayout.startActivityForResult(intent, requestCode);
        }
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

    public boolean dismissDialogOnPause(Dialog dialog) {
        return true;
    }

    public boolean canBeginSlide() {
        return true;
    }

    public void onBeginSlide() {
        try {
            if (this.visibleDialog != null && this.visibleDialog.isShowing()) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        ActionBar actionBar = this.actionBar;
        if (actionBar != null) {
            actionBar.onPause();
        }
    }

    protected void onTransitionAnimationStart(boolean isOpen, boolean backward) {
    }

    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
    }

    protected void onBecomeFullyVisible() {
        ActionBar actionBar;
        AccessibilityManager mgr = (AccessibilityManager) ApplicationLoader.applicationContext.getSystemService("accessibility");
        if (mgr.isEnabled() && (actionBar = getActionBar()) != null) {
            String title = actionBar.getTitle();
            if (!TextUtils.isEmpty(title)) {
                setParentActivityTitle(title);
            }
        }
    }

    protected void onBecomeFullyHidden() {
    }

    protected AnimatorSet onCustomTransitionAnimation(boolean isOpen, Runnable callback) {
        return null;
    }

    public void onLowMemory() {
    }

    public Dialog showDialog(Dialog dialog) {
        return showDialog(dialog, false, null);
    }

    public Dialog showDialog(Dialog dialog, DialogInterface.OnDismissListener onDismissListener) {
        return showDialog(dialog, false, onDismissListener);
    }

    public Dialog showDialog(Dialog dialog, boolean allowInTransition, final DialogInterface.OnDismissListener onDismissListener) {
        ActionBarLayout actionBarLayout;
        if (dialog == null || (actionBarLayout = this.parentLayout) == null || actionBarLayout.animationInProgress || this.parentLayout.startedTracking || (!allowInTransition && this.parentLayout.checkTransitionAnimation())) {
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
            this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$BaseFragment$eWnG4TxHXXvwsgEpbu9wjrI1Tqo
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$showDialog$0$BaseFragment(onDismissListener, dialogInterface);
                }
            });
            this.visibleDialog.show();
            return this.visibleDialog;
        } catch (Exception e2) {
            FileLog.e(e2);
            return null;
        }
    }

    public /* synthetic */ void lambda$showDialog$0$BaseFragment(DialogInterface.OnDismissListener onDismissListener, DialogInterface dialog1) {
        if (onDismissListener != null) {
            onDismissListener.onDismiss(dialog1);
        }
        onDialogDismiss(this.visibleDialog);
        this.visibleDialog = null;
    }

    protected void onDialogDismiss(Dialog dialog) {
    }

    public Dialog getVisibleDialog() {
        return this.visibleDialog;
    }

    public void setVisibleDialog(Dialog dialog) {
        this.visibleDialog = dialog;
    }

    public boolean extendActionMode(Menu menu) {
        return false;
    }

    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[0];
    }

    public AccountInstance getAccountInstance() {
        return AccountInstance.getInstance(this.currentAccount);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public MessagesController getMessagesController() {
        return getAccountInstance().getMessagesController();
    }

    protected ContactsController getContactsController() {
        return getAccountInstance().getContactsController();
    }

    protected MediaDataController getMediaDataController() {
        return getAccountInstance().getMediaDataController();
    }

    /* JADX INFO: Access modifiers changed from: protected */
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

    protected FileLoader getFileLoader() {
        return getAccountInstance().getFileLoader();
    }

    protected SecretChatHelper getSecretChatHelper() {
        return getAccountInstance().getSecretChatHelper();
    }

    protected DownloadController getDownloadController() {
        return getAccountInstance().getDownloadController();
    }

    protected SharedPreferences getNotificationsSettings() {
        return getAccountInstance().getNotificationsSettings();
    }

    public NotificationCenter getNotificationCenter() {
        return getAccountInstance().getNotificationCenter();
    }

    public MediaController getMediaController() {
        return MediaController.getInstance();
    }

    public UserConfig getUserConfig() {
        return getAccountInstance().getUserConfig();
    }

    public WalletController getWalletController() {
        return getAccountInstance().getWalletController();
    }

    public void useButterKnife() {
        View view = this.fragmentView;
        if (view != null) {
            this.unbinder = ButterKnife.bind(this, view);
        }
    }

    public int getNavigationBarColor() {
        return Theme.getColor(Theme.key_windowBackgroundGray);
    }

    public void setNavigationBarColor(int color) {
        Activity activity = getParentActivity();
        if (activity != null) {
            Window window = activity.getWindow();
            if (Build.VERSION.SDK_INT >= 26 && window != null && window.getNavigationBarColor() != color) {
                window.setNavigationBarColor(color);
                float brightness = AndroidUtilities.computePerceivedBrightness(color);
                AndroidUtilities.setLightNavigationBar(window, brightness >= 0.721f);
            }
        }
    }
}
