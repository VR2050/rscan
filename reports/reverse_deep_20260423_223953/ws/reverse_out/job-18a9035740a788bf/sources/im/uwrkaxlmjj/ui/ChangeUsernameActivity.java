package im.uwrkaxlmjj.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.text.Editable;
import android.text.InputFilter;
import android.text.Selection;
import android.text.Spannable;
import android.text.Spanned;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
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
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.filter.MaxByteLengthFilter;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChangeUsernameActivity extends BaseFragment {
    private static final int done_button = 1;
    private int checkReqId;
    private Runnable checkRunnable;
    private TextView checkTextView;
    private View doneButton;
    private MryEditText etAppCode;
    private TextView helpTextView;
    private boolean ignoreCheck;
    private ImageView ivClear;
    private String lastCheckName;
    private boolean lastNameAvailable;

    public class LinkSpan extends ClickableSpan {
        private String url;

        public LinkSpan(String value) {
            this.url = value;
        }

        @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
        public void updateDrawState(TextPaint ds) {
            super.updateDrawState(ds);
            ds.setUnderlineText(false);
        }

        @Override // android.text.style.ClickableSpan
        public void onClick(View widget) {
            try {
                ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
                ClipData clip = ClipData.newPlainText("label", this.url);
                clipboard.setPrimaryClip(clip);
                ToastUtils.show(R.string.LinkCopied);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString(R.string.ChangeAppNameCode));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ChangeUsernameActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ChangeUsernameActivity.this.finishFragment();
                } else if (id == 1) {
                    ChangeUsernameActivity.this.saveName();
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        this.doneButton = menu.addItem(1, LocaleController.getString(R.string.Done));
        TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
        if (user == null) {
            user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
        }
        this.fragmentView = new LinearLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        LinearLayout linearLayout = (LinearLayout) this.fragmentView;
        linearLayout.setOrientation(1);
        this.fragmentView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$PNtXQE6XKGLdVJZZ3o5IB38udT0
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ChangeUsernameActivity.lambda$createView$0(view, motionEvent);
            }
        });
        FrameLayout nameContainer = new FrameLayout(context);
        nameContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        nameContainer.setPadding(AndroidUtilities.dp(15.0f), 0, AndroidUtilities.dp(15.0f), 0);
        linearLayout.addView(nameContainer, LayoutHelper.createLinear(-1, 55, 10.0f, 10.0f, 10.0f, 10.0f));
        MryEditText mryEditText = new MryEditText(context);
        this.etAppCode = mryEditText;
        mryEditText.setTextSize(16.0f);
        this.etAppCode.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        this.etAppCode.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.etAppCode.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.etAppCode.setMaxLines(1);
        this.etAppCode.setLines(1);
        this.etAppCode.setSingleLine(true);
        this.etAppCode.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
        this.etAppCode.setInputType(180224);
        this.etAppCode.setImeOptions(6);
        this.etAppCode.setHint(LocaleController.getString(R.string.EmptyAppNameCodeTips));
        this.etAppCode.setFilters(new InputFilter[]{new MaxByteLengthFilter()});
        this.etAppCode.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.ChangeUsernameActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
                if (!ChangeUsernameActivity.this.ignoreCheck && ChangeUsernameActivity.this.checkTextView != null) {
                    ChangeUsernameActivity changeUsernameActivity = ChangeUsernameActivity.this;
                    changeUsernameActivity.checkUserName(changeUsernameActivity.etAppCode.getText().toString(), false);
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable editable) {
                if (editable == null || editable.toString().trim().length() == 0) {
                    if (ChangeUsernameActivity.this.doneButton != null) {
                        ChangeUsernameActivity.this.doneButton.setEnabled(false);
                        ChangeUsernameActivity.this.doneButton.setAlpha(0.5f);
                    }
                    if (ChangeUsernameActivity.this.ivClear != null) {
                        ChangeUsernameActivity.this.ivClear.setVisibility(8);
                        return;
                    }
                    return;
                }
                if (ChangeUsernameActivity.this.doneButton != null) {
                    ChangeUsernameActivity.this.doneButton.setEnabled(true);
                    ChangeUsernameActivity.this.doneButton.setAlpha(1.0f);
                }
                if (ChangeUsernameActivity.this.ivClear != null) {
                    ChangeUsernameActivity.this.ivClear.setVisibility(0);
                }
            }
        });
        this.etAppCode.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$6WXKMvBQKEme5nr7IuE6XPqNUMs
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i, KeyEvent keyEvent) {
                return this.f$0.lambda$createView$1$ChangeUsernameActivity(textView, i, keyEvent);
            }
        });
        this.etAppCode.setFilters(new InputFilter[]{new InputFilter() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$nuc4oKMkXyA0YdCRpjJLs2ExXRo
            @Override // android.text.InputFilter
            public final CharSequence filter(CharSequence charSequence, int i, int i2, Spanned spanned, int i3, int i4) {
                return ChangeUsernameActivity.lambda$createView$2(charSequence, i, i2, spanned, i3, i4);
            }
        }});
        nameContainer.addView(this.etAppCode, LayoutHelper.createFrame(-1, -1, 0, 0, AndroidUtilities.dp(20.0f), 0));
        ImageView imageView = new ImageView(context);
        this.ivClear = imageView;
        imageView.setImageResource(R.id.ic_clear_remarks);
        nameContainer.addView(this.ivClear, LayoutHelper.createFrame(-2, -2, 21));
        this.ivClear.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$k5vp-t3zO0qxybdMn8zFb1buNiM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$3$ChangeUsernameActivity(view);
            }
        });
        TextView textView = new TextView(context);
        this.checkTextView = textView;
        textView.setTextSize(1, 15.0f);
        this.checkTextView.setGravity(LocaleController.isRTL ? 5 : 3);
        linearLayout.addView(this.checkTextView, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3, 24, 10, 24, 0));
        TextView textView2 = new TextView(context);
        this.helpTextView = textView2;
        textView2.setTextSize(1, 15.0f);
        this.helpTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText8));
        this.helpTextView.setGravity(LocaleController.isRTL ? 5 : 3);
        this.helpTextView.setText(TextUtils.concat(LocaleController.getString("AppCodeHelp1", R.string.AppCodeHelp1) + "\n\n" + LocaleController.getString("AppCodeHelp2", R.string.AppCodeHelp2)));
        this.helpTextView.setLinkTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteLinkText));
        this.helpTextView.setHighlightColor(Theme.getColor(Theme.key_windowBackgroundWhiteLinkSelection));
        this.helpTextView.setMovementMethod(new LinkMovementMethodMy());
        linearLayout.addView(this.helpTextView, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3, 24, 10, 24, 0));
        this.checkTextView.setVisibility(8);
        if (user != null && user.username != null && user.username.length() > 0) {
            this.ignoreCheck = true;
            this.etAppCode.setText(user.username);
            MryEditText mryEditText2 = this.etAppCode;
            mryEditText2.setSelection(mryEditText2.length());
            this.ignoreCheck = false;
        }
        return this.fragmentView;
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ boolean lambda$createView$1$ChangeUsernameActivity(TextView textView, int i, KeyEvent keyEvent) {
        View view;
        if (i == 6 && (view = this.doneButton) != null) {
            view.performClick();
            return true;
        }
        return false;
    }

    static /* synthetic */ CharSequence lambda$createView$2(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {
        if (source != null && " ".equals(source.toString())) {
            return "";
        }
        return null;
    }

    public /* synthetic */ void lambda$createView$3$ChangeUsernameActivity(View v) {
        MryEditText mryEditText = this.etAppCode;
        if (mryEditText != null) {
            mryEditText.setText((CharSequence) null);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        boolean animations = preferences.getBoolean("view_animations", true);
        if (!animations) {
            this.etAppCode.requestFocus();
            AndroidUtilities.showKeyboard(this.etAppCode);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkUserName(final String name, boolean alert) {
        if (name != null && name.length() > 0) {
            this.checkTextView.setVisibility(0);
        } else {
            this.checkTextView.setVisibility(8);
        }
        if (alert && name.length() == 0) {
            return true;
        }
        Runnable runnable = this.checkRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.checkRunnable = null;
            this.lastCheckName = null;
            if (this.checkReqId != 0) {
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.checkReqId, true);
            }
        }
        this.lastNameAvailable = false;
        if (name != null) {
            if (name.startsWith("_") || name.endsWith("_")) {
                this.checkTextView.setText(LocaleController.getString("UsernameInvalid", R.string.UsernameInvalid));
                this.checkTextView.setTag(Theme.key_windowBackgroundWhiteRedText4);
                this.checkTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText4));
                return false;
            }
            for (int a = 0; a < name.length(); a++) {
                char ch = name.charAt(a);
                if (a == 0 && ch >= '0' && ch <= '9') {
                    if (!alert) {
                        this.checkTextView.setText(LocaleController.getString("UsernameInvalidStartNumber", R.string.UsernameInvalidStartNumber));
                        this.checkTextView.setTag(Theme.key_windowBackgroundWhiteRedText4);
                        this.checkTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText4));
                    } else {
                        WalletDialogUtil.showSingleBtnWalletDialog(this, null, LocaleController.getString("UsernameInvalidStartNumber", R.string.UsernameInvalidStartNumber), LocaleController.getString(R.string.OK), true, null, null);
                    }
                    return false;
                }
                if ((ch < '0' || ch > '9') && ((ch < 'a' || ch > 'z') && ((ch < 'A' || ch > 'Z') && ch != '_'))) {
                    if (alert) {
                        WalletDialogUtil.showSingleBtnWalletDialog(this, null, LocaleController.getString("UsernameInvalid", R.string.UsernameInvalid), LocaleController.getString(R.string.OK), true, null, null);
                    } else {
                        this.checkTextView.setText(LocaleController.getString("UsernameInvalid", R.string.UsernameInvalid));
                        this.checkTextView.setTag(Theme.key_windowBackgroundWhiteRedText4);
                        this.checkTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText4));
                    }
                    return false;
                }
            }
        }
        if (name == null || name.length() == 0 || name.length() < 5) {
            if (name == null || name.length() == 0) {
                if (!alert) {
                    this.checkTextView.setText(LocaleController.getString("NoAppNameCodePleaseReEnter", R.string.NoAppNameCodePleaseReEnter));
                } else {
                    WalletDialogUtil.showSingleBtnWalletDialog(this, null, LocaleController.getString("NoAppNameCodePleaseReEnter", R.string.NoAppNameCodePleaseReEnter), LocaleController.getString(R.string.OK), true, null, null);
                }
            } else if (!alert) {
                this.checkTextView.setText(LocaleController.getString("UsernameInvalidShort", R.string.UsernameInvalidShort));
            } else {
                WalletDialogUtil.showSingleBtnWalletDialog(this, null, LocaleController.getString("UsernameInvalidShort", R.string.UsernameInvalidShort), LocaleController.getString(R.string.OK), true, null, null);
            }
            this.checkTextView.setTag(Theme.key_windowBackgroundWhiteRedText4);
            this.checkTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText4));
            return false;
        }
        if (name.length() > 24) {
            if (!alert) {
                this.checkTextView.setText(LocaleController.getString("UsernameInvalidLong", R.string.UsernameInvalidLong));
                this.checkTextView.setTag(Theme.key_windowBackgroundWhiteRedText4);
                this.checkTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText4));
            } else {
                WalletDialogUtil.showSingleBtnWalletDialog(this, null, LocaleController.getString("UsernameInvalidLong", R.string.UsernameInvalidLong), LocaleController.getString(R.string.OK), true, null, null);
            }
            return false;
        }
        if (!alert) {
            String currentName = UserConfig.getInstance(this.currentAccount).getCurrentUser().username;
            if (currentName == null) {
                currentName = "";
            }
            if (name.equals(currentName)) {
                this.checkTextView.setText(LocaleController.formatString("UsernameAvailable", R.string.UsernameAvailable, name));
                this.checkTextView.setTag(Theme.key_windowBackgroundWhiteGreenText);
                this.checkTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGreenText));
                return true;
            }
            this.checkTextView.setVisibility(8);
            this.lastCheckName = name;
            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$tR6cEDpkgE-JtoWfHqj6bJbBToc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$checkUserName$6$ChangeUsernameActivity(name);
                }
            };
            this.checkRunnable = runnable2;
            AndroidUtilities.runOnUIThread(runnable2, 300L);
        }
        return true;
    }

    public /* synthetic */ void lambda$checkUserName$6$ChangeUsernameActivity(final String name) {
        TLRPC.TL_account_checkUsername req = new TLRPC.TL_account_checkUsername();
        req.username = name;
        this.checkReqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$5Km7DnG13TzbyCQyNCgjGwY4ytM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$5$ChangeUsernameActivity(name, tLObject, tL_error);
            }
        }, 2);
    }

    public /* synthetic */ void lambda$null$5$ChangeUsernameActivity(final String name, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$suVK_O8zUxZ0PFKu8GsmxNY-TEo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$4$ChangeUsernameActivity(name, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$4$ChangeUsernameActivity(String name, TLRPC.TL_error error, TLObject response) {
        this.checkReqId = 0;
        String str = this.lastCheckName;
        if (str != null && str.equals(name)) {
            if (error == null && (response instanceof TLRPC.TL_boolTrue)) {
                this.lastNameAvailable = true;
                return;
            }
            this.checkTextView.setText(LocaleController.getString("UsernameInUse", R.string.UsernameInUse));
            this.checkTextView.setTag(Theme.key_windowBackgroundWhiteRedText4);
            this.checkTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText4));
            this.checkTextView.setVisibility(0);
            this.lastNameAvailable = false;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveName() {
        String ret = this.etAppCode.getText().toString();
        if (TextUtils.isEmpty(ret)) {
            WalletDialogUtil.showSingleBtnWalletDialog(this, null, LocaleController.getString("NoAppNameCodePleaseReEnter", R.string.NoAppNameCodePleaseReEnter), LocaleController.getString(R.string.OK), true, null, null);
            return;
        }
        if (!checkUserName(ret, true)) {
            return;
        }
        this.checkTextView.setVisibility(8);
        TLRPC.User user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
        if (getParentActivity() == null || user == null) {
            return;
        }
        String currentName = user.username;
        if (currentName == null) {
            currentName = "";
        }
        String newName = this.etAppCode.getText().toString();
        if (currentName.equals(newName)) {
            finishFragment();
            return;
        }
        final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
        progressDialog.setLoadingText(LocaleController.getString(R.string.SettingUp));
        TLRPC.TL_account_updateUsername req = new TLRPC.TL_account_updateUsername();
        req.username = newName;
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.updateInterfaces, 1);
        final int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$P7rjENISwN9D7LN5R5Sh365HfRA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$saveName$10$ChangeUsernameActivity(progressDialog, tLObject, tL_error);
            }
        }, 2);
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$O6FVtIOqqpfDP1A78YVo_HgaG3E
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$saveName$11$ChangeUsernameActivity(reqId, dialogInterface);
            }
        });
        progressDialog.show();
    }

    public /* synthetic */ void lambda$saveName$10$ChangeUsernameActivity(final XAlertDialog progressDialog, TLObject response, final TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.User user1 = (TLRPC.User) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$dyfZku69p5aQOamKKKWgI8fdlaQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$8$ChangeUsernameActivity(progressDialog, user1);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$CgIMLC5EqHJsWDy2C3h2YZcp5gc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$9$ChangeUsernameActivity(progressDialog, error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$8$ChangeUsernameActivity(final XAlertDialog progressDialog, TLRPC.User user1) {
        try {
            progressDialog.setLoadingImage(getParentActivity().getResources().getDrawable(R.id.ic_apply_send_done), AndroidUtilities.dp(30.0f), AndroidUtilities.dp(20.0f));
            progressDialog.setLoadingText(LocaleController.getString(R.string.SetupSuccess));
            this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangeUsernameActivity$PsA2K3Tc786dp_K5ikP9tKAOlYg
                @Override // java.lang.Runnable
                public final void run() {
                    progressDialog.dismiss();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        } catch (Exception e) {
            FileLog.e(e);
        }
        ArrayList<TLRPC.User> users = new ArrayList<>();
        users.add(user1);
        MessagesController.getInstance(this.currentAccount).putUsers(users, false);
        MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, false, true);
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
        finishFragment();
    }

    public /* synthetic */ void lambda$null$9$ChangeUsernameActivity(XAlertDialog progressDialog, TLRPC.TL_error error) {
        String msg;
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if ("ALREDY_CHANGE".equals(error.text)) {
            msg = LocaleController.getString("AlreadyChangeAppNameCodeTips", R.string.AlreadyChangeAppNameCodeTips);
        } else {
            msg = LocaleController.getString(R.string.OperationFailedPleaseTryAgain);
        }
        WalletDialogUtil.showSingleBtnWalletDialog(this, LocaleController.getString(R.string.SetupAppNameCodeFail), msg, LocaleController.getString(R.string.OK), true, null, null);
    }

    public /* synthetic */ void lambda$saveName$11$ChangeUsernameActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        if (isOpen) {
            this.etAppCode.requestFocus();
            AndroidUtilities.showKeyboard(this.etAppCode);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.helpTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText8), new ThemeDescription(this.checkTextView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundWhiteRedText4), new ThemeDescription(this.checkTextView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundWhiteGreenText), new ThemeDescription(this.checkTextView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText8)};
    }
}
