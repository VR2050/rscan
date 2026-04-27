package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.filter.MaxByteLengthFilter;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChangeNameActivity extends BaseFragment {
    private static final int done_button = 1;
    private View doneButton;
    private MryEditText etNickname;
    private ImageView ivClear;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("EditNickname", R.string.EditNickname));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ChangeNameActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ChangeNameActivity.this.finishFragment();
                } else if (id == 1) {
                    ChangeNameActivity.this.saveName();
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        this.doneButton = menu.addItem(1, LocaleController.getString(R.string.Done));
        TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
        if (user == null) {
            user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
        }
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.fragmentView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeNameActivity$l2uxvfUStns6TbTARKnygd0vgbU
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ChangeNameActivity.lambda$createView$0(view, motionEvent);
            }
        });
        FrameLayout nameContainer = new FrameLayout(context);
        nameContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        nameContainer.setPadding(AndroidUtilities.dp(15.0f), 0, AndroidUtilities.dp(15.0f), 0);
        ((FrameLayout) this.fragmentView).addView(nameContainer, LayoutHelper.createFrame(-1, 55, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        MryEditText mryEditText = new MryEditText(context);
        this.etNickname = mryEditText;
        mryEditText.setTextSize(16.0f);
        this.etNickname.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        this.etNickname.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.etNickname.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.etNickname.setMaxLines(1);
        this.etNickname.setLines(1);
        this.etNickname.setSingleLine(true);
        this.etNickname.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
        this.etNickname.setInputType(49152);
        this.etNickname.setImeOptions(6);
        this.etNickname.setHint(LocaleController.getString(R.string.EmptyNicknameTips));
        this.etNickname.setFilters(new InputFilter[]{new MaxByteLengthFilter()});
        this.etNickname.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.ChangeNameActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                if (s == null || s.toString().trim().length() == 0) {
                    if (ChangeNameActivity.this.doneButton != null) {
                        ChangeNameActivity.this.doneButton.setEnabled(false);
                        ChangeNameActivity.this.doneButton.setAlpha(0.5f);
                    }
                    if (ChangeNameActivity.this.ivClear != null) {
                        ChangeNameActivity.this.ivClear.setVisibility(8);
                        return;
                    }
                    return;
                }
                if (ChangeNameActivity.this.doneButton != null) {
                    ChangeNameActivity.this.doneButton.setEnabled(true);
                    ChangeNameActivity.this.doneButton.setAlpha(1.0f);
                }
                if (ChangeNameActivity.this.ivClear != null) {
                    ChangeNameActivity.this.ivClear.setVisibility(0);
                }
            }
        });
        this.etNickname.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeNameActivity$gNk4bwxHa8PVmqVIM4dS7TWJ-I8
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i, KeyEvent keyEvent) {
                return this.f$0.lambda$createView$1$ChangeNameActivity(textView, i, keyEvent);
            }
        });
        nameContainer.addView(this.etNickname, LayoutHelper.createFrame(-1, -1, 0, 0, AndroidUtilities.dp(20.0f), 0));
        ImageView imageView = new ImageView(context);
        this.ivClear = imageView;
        imageView.setImageResource(R.id.ic_clear_remarks);
        nameContainer.addView(this.ivClear, LayoutHelper.createFrame(-2, -2, 21));
        this.ivClear.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeNameActivity$Zhfp55p5XIHl4S1QnPXWRrLVm-A
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$2$ChangeNameActivity(view);
            }
        });
        if (user != null) {
            this.etNickname.setText(user.first_name);
            if (this.etNickname.getText() != null) {
                MryEditText mryEditText2 = this.etNickname;
                mryEditText2.setSelection(mryEditText2.getText().length());
            }
        }
        return this.fragmentView;
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ boolean lambda$createView$1$ChangeNameActivity(TextView textView, int i, KeyEvent keyEvent) {
        View view;
        if (i == 6 && (view = this.doneButton) != null) {
            view.performClick();
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$createView$2$ChangeNameActivity(View v) {
        MryEditText mryEditText = this.etNickname;
        if (mryEditText != null) {
            mryEditText.setText((CharSequence) null);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        MryEditText mryEditText;
        super.onResume();
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        boolean animations = preferences.getBoolean("view_animations", true);
        if (!animations && (mryEditText = this.etNickname) != null) {
            mryEditText.requestFocus();
            AndroidUtilities.showKeyboard(this.etNickname);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveName() {
        TLRPC.User currentUser = UserConfig.getInstance(this.currentAccount).getCurrentUser();
        if (currentUser == null) {
            return;
        }
        String newFirst = this.etNickname.getText().toString();
        if (TextUtils.isEmpty(newFirst)) {
            ToastUtils.show(R.string.EmptyNameTips);
            return;
        }
        if (currentUser.first_name != null && currentUser.first_name.equals(newFirst)) {
            finishFragment();
            return;
        }
        TLRPC.TL_account_updateProfile req = new TLRPC.TL_account_updateProfile();
        req.flags = 3;
        req.first_name = newFirst;
        req.last_name = "";
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeNameActivity$XBj-okYJXoP99Ron-6yIBDb3mwQ
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$saveName$4$ChangeNameActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$saveName$4$ChangeNameActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeNameActivity$ibiixOeKPNvsI46Dxoki-LkyMAY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$ChangeNameActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$ChangeNameActivity(TLRPC.TL_error error, TLObject response) {
        TLRPC.User user;
        if (error != null) {
            ToastUtils.show(R.string.ModifyFail);
            return;
        }
        TLRPC.User newUser = (TLRPC.User) response;
        if (newUser != null && (user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()))) != null) {
            user.first_name = newUser.first_name;
            user.last_name = newUser.last_name;
        }
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.updateInterfaces, 1);
        ToastUtils.show(R.string.ModifySuccess);
        finishFragment();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        if (isOpen) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeNameActivity$bwdXG68RGz_wT7vfLQPdQDOc4SA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onTransitionAnimationEnd$5$ChangeNameActivity();
                }
            }, 100L);
        }
    }

    public /* synthetic */ void lambda$onTransitionAnimationEnd$5$ChangeNameActivity() {
        MryEditText mryEditText = this.etNickname;
        if (mryEditText != null) {
            mryEditText.requestFocus();
            AndroidUtilities.showKeyboard(this.etNickname);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector)};
    }
}
