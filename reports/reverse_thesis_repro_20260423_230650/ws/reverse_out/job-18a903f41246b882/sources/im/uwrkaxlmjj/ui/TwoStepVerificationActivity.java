package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Vibrator;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SRPHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.EditTextSettingsCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.math.BigInteger;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class TwoStepVerificationActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int done_button = 1;
    private int abortPasswordRow;
    private TextView bottomButton;
    private TextView bottomTextView;
    private int changePasswordRow;
    private int changeRecoveryEmailRow;
    private boolean closeAfterSet;
    private EditTextSettingsCell codeFieldCell;
    private TLRPC.TL_account_password currentPassword;
    private byte[] currentPasswordHash;
    private byte[] currentSecret;
    private long currentSecretId;
    private TwoStepVerificationActivityDelegate delegate;
    private boolean destroyed;
    private ActionBarMenuItem doneItem;
    private AnimatorSet doneItemAnimation;
    private String email;
    private int emailCodeLength;
    private boolean emailOnly;
    private EmptyTextProgressView emptyView;
    private String firstPassword;
    private String hint;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private boolean loading;
    private int passwordCodeFieldRow;
    private EditTextBoldCursor passwordEditText;
    private int passwordEnabledDetailRow;
    private boolean passwordEntered;
    private int passwordSetState;
    private int passwordSetupDetailRow;
    private boolean paused;
    private AlertDialog progressDialog;
    private ContextProgressView progressView;
    private int resendCodeRow;
    private int rowCount;
    private ScrollView scrollView;
    private int setPasswordDetailRow;
    private int setPasswordRow;
    private int setRecoveryEmailRow;
    private int shadowRow;
    private Runnable shortPollRunnable;
    private TextView titleTextView;
    private int turnPasswordOffRow;
    private int type;
    private boolean waitingForEmail;

    public interface TwoStepVerificationActivityDelegate {
        void didEnterPassword(TLRPC.InputCheckPasswordSRP inputCheckPasswordSRP);
    }

    public TwoStepVerificationActivity(int type) {
        this.emailCodeLength = 6;
        this.passwordEntered = true;
        this.currentPasswordHash = new byte[0];
        this.type = type;
        if (type == 0) {
            loadPasswordInfo(false);
        }
    }

    public TwoStepVerificationActivity(int account, int type) {
        this.emailCodeLength = 6;
        this.passwordEntered = true;
        this.currentPasswordHash = new byte[0];
        this.currentAccount = account;
        this.type = type;
        if (type == 0) {
            loadPasswordInfo(false);
        }
    }

    protected void setRecoveryParams(TLRPC.TL_account_password password) {
        this.currentPassword = password;
        this.passwordSetState = 4;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        updateRows();
        if (this.type == 0) {
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didSetTwoStepPassword);
            return true;
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        if (this.type == 0) {
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didSetTwoStepPassword);
            Runnable runnable = this.shortPollRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.shortPollRunnable = null;
            }
            this.destroyed = true;
        }
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog != null) {
            try {
                alertDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            this.progressDialog = null;
        }
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.TwoStepVerificationActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    TwoStepVerificationActivity.this.finishFragment();
                } else if (id == 1) {
                    TwoStepVerificationActivity.this.processDone();
                }
            }
        });
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        ActionBarMenu menu = this.actionBar.createMenu();
        this.doneItem = menu.addItemWithWidth(1, R.drawable.ic_done, AndroidUtilities.dp(56.0f));
        ContextProgressView contextProgressView = new ContextProgressView(context, 1);
        this.progressView = contextProgressView;
        contextProgressView.setAlpha(0.0f);
        this.progressView.setScaleX(0.1f);
        this.progressView.setScaleY(0.1f);
        this.progressView.setVisibility(4);
        this.doneItem.addView(this.progressView, LayoutHelper.createFrame(-1, -1.0f));
        ScrollView scrollView = new ScrollView(context);
        this.scrollView = scrollView;
        scrollView.setFillViewport(true);
        frameLayout.addView(this.scrollView, LayoutHelper.createFrame(-1, -1.0f));
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(1);
        this.scrollView.addView(linearLayout, LayoutHelper.createScroll(-1, -2, 51));
        TextView textView = new TextView(context);
        this.titleTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
        this.titleTextView.setTextSize(1, 18.0f);
        this.titleTextView.setGravity(1);
        this.titleTextView.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), 0);
        linearLayout.addView(this.titleTextView, LayoutHelper.createLinear(-2, -2, 1, 0, 38, 0, 0));
        EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context);
        this.passwordEditText = editTextBoldCursor;
        editTextBoldCursor.setTextSize(1, 20.0f);
        this.passwordEditText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.passwordEditText.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        this.passwordEditText.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
        this.passwordEditText.setMaxLines(1);
        this.passwordEditText.setLines(1);
        this.passwordEditText.setGravity(1);
        this.passwordEditText.setSingleLine(true);
        this.passwordEditText.setInputType(TsExtractor.TS_STREAM_TYPE_AC3);
        this.passwordEditText.setTransformationMethod(PasswordTransformationMethod.getInstance());
        this.passwordEditText.setTypeface(Typeface.DEFAULT);
        this.passwordEditText.setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.passwordEditText.setCursorSize(AndroidUtilities.dp(20.0f));
        this.passwordEditText.setCursorWidth(1.5f);
        linearLayout.addView(this.passwordEditText, LayoutHelper.createLinear(-1, 36, 51, 40, 32, 40, 0));
        this.passwordEditText.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$6Uj5pL8GdI_4EhYFEAmQvi5-fkQ
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView2, int i, KeyEvent keyEvent) {
                return this.f$0.lambda$createView$0$TwoStepVerificationActivity(textView2, i, keyEvent);
            }
        });
        this.passwordEditText.setCustomSelectionActionModeCallback(new ActionMode.Callback() { // from class: im.uwrkaxlmjj.ui.TwoStepVerificationActivity.2
            @Override // android.view.ActionMode.Callback
            public boolean onPrepareActionMode(ActionMode mode, Menu menu2) {
                return false;
            }

            @Override // android.view.ActionMode.Callback
            public void onDestroyActionMode(ActionMode mode) {
            }

            @Override // android.view.ActionMode.Callback
            public boolean onCreateActionMode(ActionMode mode, Menu menu2) {
                return false;
            }

            @Override // android.view.ActionMode.Callback
            public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                return false;
            }
        });
        TextView textView2 = new TextView(context);
        this.bottomTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
        this.bottomTextView.setTextSize(1, 14.0f);
        this.bottomTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        this.bottomTextView.setText(LocaleController.getString("YourEmailInfo", R.string.YourEmailInfo));
        linearLayout.addView(this.bottomTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 40, 30, 40, 0));
        LinearLayout linearLayout2 = new LinearLayout(context);
        linearLayout2.setGravity(80);
        linearLayout.addView(linearLayout2, LayoutHelper.createLinear(-1, -1));
        TextView textView3 = new TextView(context);
        this.bottomButton = textView3;
        textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
        this.bottomButton.setTextSize(1, 14.0f);
        this.bottomButton.setGravity((LocaleController.isRTL ? 5 : 3) | 80);
        this.bottomButton.setText(LocaleController.getString("YourEmailSkip", R.string.YourEmailSkip));
        this.bottomButton.setPadding(0, AndroidUtilities.dp(10.0f), 0, 0);
        linearLayout2.addView(this.bottomButton, LayoutHelper.createLinear(-1, -2, (LocaleController.isRTL ? 5 : 3) | 80, 40, 0, 40, 14));
        this.bottomButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$YE6VIqahlfBZZSXEihGTx1ocVTw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$6$TwoStepVerificationActivity(view);
            }
        });
        int i = this.type;
        if (i == 0) {
            EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
            this.emptyView = emptyTextProgressView;
            emptyTextProgressView.showProgress();
            frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
            RecyclerListView recyclerListView = new RecyclerListView(context);
            this.listView = recyclerListView;
            recyclerListView.setLayoutManager(new LinearLayoutManager(context, 1, false));
            this.listView.setEmptyView(this.emptyView);
            this.listView.setVerticalScrollBarEnabled(false);
            frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
            RecyclerListView recyclerListView2 = this.listView;
            ListAdapter listAdapter = new ListAdapter(context);
            this.listAdapter = listAdapter;
            recyclerListView2.setAdapter(listAdapter);
            this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$JqIPXm8GChmo9_BrQuPvGPz0QOQ
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                public final void onItemClick(View view, int i2) {
                    this.f$0.lambda$createView$9$TwoStepVerificationActivity(view, i2);
                }
            });
            EditTextSettingsCell editTextSettingsCell = new EditTextSettingsCell(context);
            this.codeFieldCell = editTextSettingsCell;
            editTextSettingsCell.setTextAndHint("", LocaleController.getString("PasswordCode", R.string.PasswordCode), false);
            this.codeFieldCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            EditTextBoldCursor editText = this.codeFieldCell.getTextView();
            editText.setInputType(3);
            editText.setImeOptions(6);
            editText.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$9YcEuctj1UtVV-WxDJr27OxPGdI
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView4, int i2, KeyEvent keyEvent) {
                    return this.f$0.lambda$createView$10$TwoStepVerificationActivity(textView4, i2, keyEvent);
                }
            });
            editText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.TwoStepVerificationActivity.3
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    if (TwoStepVerificationActivity.this.emailCodeLength != 0 && s.length() == TwoStepVerificationActivity.this.emailCodeLength) {
                        TwoStepVerificationActivity.this.processDone();
                    }
                }
            });
            updateRows();
            this.actionBar.setTitle(LocaleController.getString("TwoStepVerificationTitle", R.string.TwoStepVerificationTitle));
            if (this.delegate != null) {
                this.titleTextView.setText(LocaleController.getString("PleaseEnterCurrentPasswordTransfer", R.string.PleaseEnterCurrentPasswordTransfer));
            } else {
                this.titleTextView.setText(LocaleController.getString("PleaseEnterCurrentPassword", R.string.PleaseEnterCurrentPassword));
            }
        } else if (i == 1) {
            setPasswordSetState(this.passwordSetState);
        }
        if (!this.passwordEntered || this.type == 1) {
            this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            this.fragmentView.setTag(Theme.key_windowBackgroundWhite);
        } else {
            this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
            this.fragmentView.setTag(Theme.key_windowBackgroundGray);
        }
        return this.fragmentView;
    }

    public /* synthetic */ boolean lambda$createView$0$TwoStepVerificationActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5 || i == 6) {
            processDone();
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$createView$6$TwoStepVerificationActivity(View v) {
        if (this.type == 0) {
            if (this.currentPassword.has_recovery) {
                needShowProgress();
                TLRPC.TL_auth_requestPasswordRecovery req = new TLRPC.TL_auth_requestPasswordRecovery();
                ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$3DKLd04afYnjg5IQHU_FaI7_8WQ
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$3$TwoStepVerificationActivity(tLObject, tL_error);
                    }
                }, 10);
                return;
            } else {
                if (getParentActivity() == null) {
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                builder.setNegativeButton(LocaleController.getString("RestorePasswordResetAccount", R.string.RestorePasswordResetAccount), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$aDhgYgdJW5X1b_mQv1KyKbzQWXE
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$4$TwoStepVerificationActivity(dialogInterface, i);
                    }
                });
                builder.setTitle(LocaleController.getString("RestorePasswordNoEmailTitle", R.string.RestorePasswordNoEmailTitle));
                builder.setMessage(LocaleController.getString("RestorePasswordNoEmailText", R.string.RestorePasswordNoEmailText));
                showDialog(builder.create());
                return;
            }
        }
        if (this.passwordSetState == 4) {
            showAlertWithText(LocaleController.getString("RestorePasswordNoEmailTitle", R.string.RestorePasswordNoEmailTitle), LocaleController.getString("RestoreEmailTroubleText", R.string.RestoreEmailTroubleText));
            return;
        }
        AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
        builder2.setMessage(LocaleController.getString("YourEmailSkipWarningText", R.string.YourEmailSkipWarningText));
        builder2.setTitle(LocaleController.getString("YourEmailSkipWarning", R.string.YourEmailSkipWarning));
        builder2.setPositiveButton(LocaleController.getString("YourEmailSkip", R.string.YourEmailSkip), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$4RVnIs1LOAT3ZRjNTgqpvgC9yc4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$5$TwoStepVerificationActivity(dialogInterface, i);
            }
        });
        builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder2.create());
    }

    public /* synthetic */ void lambda$null$3$TwoStepVerificationActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$r9GqUgu5x-4CUhQ0bJ-6OBZ1deU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$TwoStepVerificationActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$TwoStepVerificationActivity(TLRPC.TL_error error, TLObject response) {
        String timeString;
        needHideProgress();
        if (error == null) {
            final TLRPC.TL_auth_passwordRecovery res = (TLRPC.TL_auth_passwordRecovery) response;
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setMessage(LocaleController.formatString("RestoreEmailSent", R.string.RestoreEmailSent, res.email_pattern));
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$uN045NIALl9x5Di9HoIoa4l6ZeA
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$1$TwoStepVerificationActivity(res, dialogInterface, i);
                }
            });
            Dialog dialog = showDialog(builder.create());
            if (dialog != null) {
                dialog.setCanceledOnTouchOutside(false);
                dialog.setCancelable(false);
                return;
            }
            return;
        }
        if (error.text.startsWith("FLOOD_WAIT")) {
            int time = Utilities.parseInt(error.text).intValue();
            if (time < 60) {
                timeString = LocaleController.formatPluralString("Seconds", time);
            } else {
                timeString = LocaleController.formatPluralString("Minutes", time / 60);
            }
            showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
            return;
        }
        showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
    }

    public /* synthetic */ void lambda$null$1$TwoStepVerificationActivity(TLRPC.TL_auth_passwordRecovery res, DialogInterface dialogInterface, int i) {
        TwoStepVerificationActivity fragment = new TwoStepVerificationActivity(this.currentAccount, 1);
        TLRPC.TL_account_password tL_account_password = this.currentPassword;
        fragment.currentPassword = tL_account_password;
        tL_account_password.email_unconfirmed_pattern = res.email_pattern;
        fragment.currentSecretId = this.currentSecretId;
        fragment.currentSecret = this.currentSecret;
        fragment.passwordSetState = 4;
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$null$4$TwoStepVerificationActivity(DialogInterface dialog, int which) {
        Browser.openUrl(getParentActivity(), "https://m12345.com/deactivate?phone=" + UserConfig.getInstance(this.currentAccount).getClientPhone());
    }

    public /* synthetic */ void lambda$null$5$TwoStepVerificationActivity(DialogInterface dialogInterface, int i) {
        this.email = "";
        setNewPassword(false);
    }

    public /* synthetic */ void lambda$createView$9$TwoStepVerificationActivity(View view, int position) {
        String text;
        if (position == this.setPasswordRow || position == this.changePasswordRow) {
            TwoStepVerificationActivity fragment = new TwoStepVerificationActivity(this.currentAccount, 1);
            fragment.currentPasswordHash = this.currentPasswordHash;
            fragment.currentPassword = this.currentPassword;
            fragment.currentSecretId = this.currentSecretId;
            fragment.currentSecret = this.currentSecret;
            presentFragment(fragment);
            return;
        }
        if (position == this.setRecoveryEmailRow || position == this.changeRecoveryEmailRow) {
            TwoStepVerificationActivity fragment2 = new TwoStepVerificationActivity(this.currentAccount, 1);
            fragment2.currentPasswordHash = this.currentPasswordHash;
            fragment2.currentPassword = this.currentPassword;
            fragment2.currentSecretId = this.currentSecretId;
            fragment2.currentSecret = this.currentSecret;
            fragment2.emailOnly = true;
            fragment2.passwordSetState = 3;
            presentFragment(fragment2);
            return;
        }
        if (position == this.turnPasswordOffRow || position == this.abortPasswordRow) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            if (position == this.abortPasswordRow) {
                TLRPC.TL_account_password tL_account_password = this.currentPassword;
                if (tL_account_password != null && tL_account_password.has_password) {
                    text = LocaleController.getString("CancelEmailQuestion", R.string.CancelEmailQuestion);
                } else {
                    text = LocaleController.getString("CancelPasswordQuestion", R.string.CancelPasswordQuestion);
                }
            } else {
                text = LocaleController.getString("TurnPasswordOffQuestion", R.string.TurnPasswordOffQuestion);
                if (this.currentPassword.has_secure_values) {
                    text = text + "\n\n" + LocaleController.getString("TurnPasswordOffPassport", R.string.TurnPasswordOffPassport);
                }
            }
            builder.setMessage(text);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$E5j94X50cE3AZu2WDfujdqRhth0
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$7$TwoStepVerificationActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
            return;
        }
        if (position == this.resendCodeRow) {
            TLRPC.TL_account_resendPasswordEmail req = new TLRPC.TL_account_resendPasswordEmail();
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$z6v5BB9C7Enb3v71_YiWfEL4baM
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    TwoStepVerificationActivity.lambda$null$8(tLObject, tL_error);
                }
            });
            AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
            builder2.setMessage(LocaleController.getString("ResendCodeInfo", R.string.ResendCodeInfo));
            builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            showDialog(builder2.create());
        }
    }

    public /* synthetic */ void lambda$null$7$TwoStepVerificationActivity(DialogInterface dialogInterface, int i) {
        setNewPassword(true);
    }

    static /* synthetic */ void lambda$null$8(TLObject response, TLRPC.TL_error error) {
    }

    public /* synthetic */ boolean lambda$createView$10$TwoStepVerificationActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 6) {
            processDone();
            return true;
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.didSetTwoStepPassword) {
            if (args != null && args.length > 0 && args[0] != null) {
                this.currentPasswordHash = (byte[]) args[0];
                if (this.closeAfterSet) {
                    String email = (String) args[4];
                    if (TextUtils.isEmpty(email) && this.closeAfterSet) {
                        removeSelfFromStack();
                    }
                }
            }
            loadPasswordInfo(false);
            updateRows();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        this.paused = true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        EditTextSettingsCell editTextSettingsCell;
        super.onResume();
        this.paused = false;
        int i = this.type;
        if (i == 1) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$2-57yMIqWY6AXXvfJiyvqkamkW8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onResume$11$TwoStepVerificationActivity();
                }
            }, 200L);
        } else if (i == 0 && (editTextSettingsCell = this.codeFieldCell) != null && editTextSettingsCell.getVisibility() == 0) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$yP6093gVDwxUgKVYK5BPOsCUkbg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onResume$12$TwoStepVerificationActivity();
                }
            }, 200L);
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
    }

    public /* synthetic */ void lambda$onResume$11$TwoStepVerificationActivity() {
        EditTextBoldCursor editTextBoldCursor = this.passwordEditText;
        if (editTextBoldCursor != null) {
            editTextBoldCursor.requestFocus();
            AndroidUtilities.showKeyboard(this.passwordEditText);
        }
    }

    public /* synthetic */ void lambda$onResume$12$TwoStepVerificationActivity() {
        EditTextSettingsCell editTextSettingsCell = this.codeFieldCell;
        if (editTextSettingsCell != null) {
            editTextSettingsCell.getTextView().requestFocus();
            AndroidUtilities.showKeyboard(this.codeFieldCell.getTextView());
        }
    }

    public void setCloseAfterSet(boolean value) {
        this.closeAfterSet = value;
    }

    public void setCurrentPasswordInfo(byte[] hash, TLRPC.TL_account_password password) {
        if (hash != null) {
            this.currentPasswordHash = hash;
        }
        this.currentPassword = password;
    }

    public void setDelegate(TwoStepVerificationActivityDelegate twoStepVerificationActivityDelegate) {
        this.delegate = twoStepVerificationActivityDelegate;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        EditTextSettingsCell editTextSettingsCell;
        if (isOpen) {
            int i = this.type;
            if (i == 1) {
                AndroidUtilities.showKeyboard(this.passwordEditText);
            } else if (i == 0 && (editTextSettingsCell = this.codeFieldCell) != null && editTextSettingsCell.getVisibility() == 0) {
                AndroidUtilities.showKeyboard(this.codeFieldCell.getTextView());
            }
        }
    }

    public static boolean canHandleCurrentPassword(TLRPC.TL_account_password password, boolean login) {
        if (login) {
            if (password.current_algo instanceof TLRPC.TL_passwordKdfAlgoUnknown) {
                return false;
            }
            return true;
        }
        if ((password.new_algo instanceof TLRPC.TL_passwordKdfAlgoUnknown) || (password.current_algo instanceof TLRPC.TL_passwordKdfAlgoUnknown) || (password.new_secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoUnknown)) {
            return false;
        }
        return true;
    }

    public static void initPasswordNewAlgo(TLRPC.TL_account_password password) {
        if (password.new_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
            TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) password.new_algo;
            byte[] salt = new byte[algo.salt1.length + 32];
            Utilities.random.nextBytes(salt);
            System.arraycopy(algo.salt1, 0, salt, 0, algo.salt1.length);
            algo.salt1 = salt;
        }
        if (password.new_secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) {
            TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000 algo2 = (TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) password.new_secure_algo;
            byte[] salt2 = new byte[algo2.salt.length + 32];
            Utilities.random.nextBytes(salt2);
            System.arraycopy(algo2.salt, 0, salt2, 0, algo2.salt.length);
            algo2.salt = salt2;
        }
    }

    private void loadPasswordInfo(final boolean silent) {
        if (!silent) {
            this.loading = true;
            ListAdapter listAdapter = this.listAdapter;
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
            }
        }
        TLRPC.TL_account_getPassword req = new TLRPC.TL_account_getPassword();
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$Z0zODopZGydJWdPI-GtwcHKFX4c
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadPasswordInfo$14$TwoStepVerificationActivity(silent, tLObject, tL_error);
            }
        }, 10);
    }

    public /* synthetic */ void lambda$loadPasswordInfo$14$TwoStepVerificationActivity(final boolean silent, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$jlx5dExl2SpvA8H9zAV40E2Ikbs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$13$TwoStepVerificationActivity(error, response, silent);
            }
        });
    }

    public /* synthetic */ void lambda$null$13$TwoStepVerificationActivity(TLRPC.TL_error error, TLObject response, boolean silent) {
        TLRPC.TL_account_password tL_account_password;
        if (error == null) {
            this.loading = false;
            TLRPC.TL_account_password tL_account_password2 = (TLRPC.TL_account_password) response;
            this.currentPassword = tL_account_password2;
            if (!canHandleCurrentPassword(tL_account_password2, false)) {
                AlertsCreator.showUpdateAppAlert(getParentActivity(), LocaleController.getString("UpdateAppAlert", R.string.UpdateAppAlert), true);
                return;
            }
            if (!silent) {
                byte[] bArr = this.currentPasswordHash;
                this.passwordEntered = (bArr != null && bArr.length > 0) || !this.currentPassword.has_password;
            }
            this.waitingForEmail = !TextUtils.isEmpty(this.currentPassword.email_unconfirmed_pattern);
            initPasswordNewAlgo(this.currentPassword);
            if (!this.paused && this.closeAfterSet && this.currentPassword.has_password) {
                TLRPC.PasswordKdfAlgo pendingCurrentAlgo = this.currentPassword.current_algo;
                TLRPC.SecurePasswordKdfAlgo pendingNewSecureAlgo = this.currentPassword.new_secure_algo;
                byte[] pendingSecureRandom = this.currentPassword.secure_random;
                String pendingEmail = this.currentPassword.has_recovery ? "1" : null;
                String pendingHint = this.currentPassword.hint != null ? this.currentPassword.hint : "";
                if (!this.waitingForEmail && pendingCurrentAlgo != null) {
                    NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didSetTwoStepPassword);
                    NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.didSetTwoStepPassword, null, pendingCurrentAlgo, pendingNewSecureAlgo, pendingSecureRandom, pendingEmail, pendingHint, null, null);
                    finishFragment();
                }
            }
        }
        if (this.type == 0 && !this.destroyed && this.shortPollRunnable == null && (tL_account_password = this.currentPassword) != null && !TextUtils.isEmpty(tL_account_password.email_unconfirmed_pattern)) {
            startShortpoll();
        }
        updateRows();
    }

    private void startShortpoll() {
        Runnable runnable = this.shortPollRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
        }
        Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$onFTMel66EBXMXjv2qh3ijlRWns
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$startShortpoll$15$TwoStepVerificationActivity();
            }
        };
        this.shortPollRunnable = runnable2;
        AndroidUtilities.runOnUIThread(runnable2, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
    }

    public /* synthetic */ void lambda$startShortpoll$15$TwoStepVerificationActivity() {
        if (this.shortPollRunnable == null) {
            return;
        }
        loadPasswordInfo(true);
        this.shortPollRunnable = null;
    }

    private void setPasswordSetState(int state) {
        if (this.passwordEditText == null) {
            return;
        }
        this.passwordSetState = state;
        if (state == 0) {
            this.actionBar.setTitle(LocaleController.getString("YourPassword", R.string.YourPassword));
            if (this.currentPassword.has_password) {
                this.titleTextView.setText(LocaleController.getString("PleaseEnterPassword", R.string.PleaseEnterPassword));
            } else {
                this.titleTextView.setText(LocaleController.getString("PleaseEnterFirstPassword", R.string.PleaseEnterFirstPassword));
            }
            this.passwordEditText.setImeOptions(5);
            this.passwordEditText.setTransformationMethod(PasswordTransformationMethod.getInstance());
            this.bottomTextView.setVisibility(4);
            this.bottomButton.setVisibility(4);
        } else if (state == 1) {
            this.actionBar.setTitle(LocaleController.getString("YourPassword", R.string.YourPassword));
            this.titleTextView.setText(LocaleController.getString("PleaseReEnterPassword", R.string.PleaseReEnterPassword));
            this.passwordEditText.setImeOptions(5);
            this.passwordEditText.setTransformationMethod(PasswordTransformationMethod.getInstance());
            this.bottomTextView.setVisibility(4);
            this.bottomButton.setVisibility(4);
        } else if (state == 2) {
            this.actionBar.setTitle(LocaleController.getString("PasswordHint", R.string.PasswordHint));
            this.titleTextView.setText(LocaleController.getString("PasswordHintText", R.string.PasswordHintText));
            this.passwordEditText.setImeOptions(5);
            this.passwordEditText.setTransformationMethod(null);
            this.bottomTextView.setVisibility(4);
            this.bottomButton.setVisibility(4);
        } else if (state == 3) {
            this.actionBar.setTitle(LocaleController.getString("RecoveryEmail", R.string.RecoveryEmail));
            this.titleTextView.setText(LocaleController.getString("YourEmail", R.string.YourEmail));
            this.passwordEditText.setImeOptions(5);
            this.passwordEditText.setTransformationMethod(null);
            this.passwordEditText.setInputType(33);
            this.bottomTextView.setVisibility(0);
            this.bottomButton.setVisibility(this.emailOnly ? 4 : 0);
        } else if (state == 4) {
            this.actionBar.setTitle(LocaleController.getString("PasswordRecovery", R.string.PasswordRecovery));
            this.titleTextView.setText(LocaleController.getString("PasswordCode", R.string.PasswordCode));
            this.bottomTextView.setText(LocaleController.getString("RestoreEmailSentInfo", R.string.RestoreEmailSentInfo));
            TextView textView = this.bottomButton;
            Object[] objArr = new Object[1];
            objArr[0] = this.currentPassword.email_unconfirmed_pattern != null ? this.currentPassword.email_unconfirmed_pattern : "";
            textView.setText(LocaleController.formatString("RestoreEmailTrouble", R.string.RestoreEmailTrouble, objArr));
            this.passwordEditText.setImeOptions(6);
            this.passwordEditText.setTransformationMethod(null);
            this.passwordEditText.setInputType(3);
            this.bottomTextView.setVisibility(0);
            this.bottomButton.setVisibility(0);
        }
        this.passwordEditText.setText("");
    }

    private void updateRows() {
        StringBuilder lastValue = new StringBuilder();
        lastValue.append(this.setPasswordRow);
        lastValue.append(this.setPasswordDetailRow);
        lastValue.append(this.changePasswordRow);
        lastValue.append(this.turnPasswordOffRow);
        lastValue.append(this.setRecoveryEmailRow);
        lastValue.append(this.changeRecoveryEmailRow);
        lastValue.append(this.resendCodeRow);
        lastValue.append(this.abortPasswordRow);
        lastValue.append(this.passwordSetupDetailRow);
        lastValue.append(this.passwordCodeFieldRow);
        lastValue.append(this.passwordEnabledDetailRow);
        lastValue.append(this.shadowRow);
        lastValue.append(this.rowCount);
        boolean wasCodeField = this.passwordCodeFieldRow != -1;
        this.rowCount = 0;
        this.setPasswordRow = -1;
        this.setPasswordDetailRow = -1;
        this.changePasswordRow = -1;
        this.turnPasswordOffRow = -1;
        this.setRecoveryEmailRow = -1;
        this.changeRecoveryEmailRow = -1;
        this.abortPasswordRow = -1;
        this.resendCodeRow = -1;
        this.passwordSetupDetailRow = -1;
        this.passwordCodeFieldRow = -1;
        this.passwordEnabledDetailRow = -1;
        this.shadowRow = -1;
        if (!this.loading) {
            if (this.waitingForEmail) {
                int i = 0 + 1;
                this.rowCount = i;
                this.passwordCodeFieldRow = 0;
                int i2 = i + 1;
                this.rowCount = i2;
                this.passwordSetupDetailRow = i;
                int i3 = i2 + 1;
                this.rowCount = i3;
                this.resendCodeRow = i2;
                int i4 = i3 + 1;
                this.rowCount = i4;
                this.abortPasswordRow = i3;
                this.rowCount = i4 + 1;
                this.shadowRow = i4;
            } else {
                TLRPC.TL_account_password tL_account_password = this.currentPassword;
                if (tL_account_password != null && tL_account_password.has_password) {
                    int i5 = this.rowCount;
                    int i6 = i5 + 1;
                    this.rowCount = i6;
                    this.changePasswordRow = i5;
                    this.rowCount = i6 + 1;
                    this.turnPasswordOffRow = i6;
                    if (this.currentPassword.has_recovery) {
                        int i7 = this.rowCount;
                        this.rowCount = i7 + 1;
                        this.changeRecoveryEmailRow = i7;
                    } else {
                        int i8 = this.rowCount;
                        this.rowCount = i8 + 1;
                        this.setRecoveryEmailRow = i8;
                    }
                    int i9 = this.rowCount;
                    this.rowCount = i9 + 1;
                    this.passwordEnabledDetailRow = i9;
                } else {
                    int i10 = this.rowCount;
                    int i11 = i10 + 1;
                    this.rowCount = i11;
                    this.setPasswordRow = i10;
                    this.rowCount = i11 + 1;
                    this.setPasswordDetailRow = i11;
                }
            }
        }
        StringBuilder newValue = new StringBuilder();
        newValue.append(this.setPasswordRow);
        newValue.append(this.setPasswordDetailRow);
        newValue.append(this.changePasswordRow);
        newValue.append(this.turnPasswordOffRow);
        newValue.append(this.setRecoveryEmailRow);
        newValue.append(this.changeRecoveryEmailRow);
        newValue.append(this.resendCodeRow);
        newValue.append(this.abortPasswordRow);
        newValue.append(this.passwordSetupDetailRow);
        newValue.append(this.passwordCodeFieldRow);
        newValue.append(this.passwordEnabledDetailRow);
        newValue.append(this.shadowRow);
        newValue.append(this.rowCount);
        if (this.listAdapter != null && !lastValue.toString().equals(newValue.toString())) {
            this.listAdapter.notifyDataSetChanged();
            if (this.passwordCodeFieldRow == -1 && getParentActivity() != null && wasCodeField) {
                AndroidUtilities.hideKeyboard(getParentActivity().getCurrentFocus());
                this.codeFieldCell.setText("", false);
            }
        }
        if (this.fragmentView != null) {
            if (this.loading || this.passwordEntered) {
                RecyclerListView recyclerListView = this.listView;
                if (recyclerListView != null) {
                    recyclerListView.setVisibility(0);
                    this.scrollView.setVisibility(4);
                    this.listView.setEmptyView(this.emptyView);
                }
                if (this.waitingForEmail && this.currentPassword != null) {
                    this.doneItem.setVisibility(0);
                } else if (this.passwordEditText != null) {
                    this.doneItem.setVisibility(8);
                    this.passwordEditText.setVisibility(4);
                    this.titleTextView.setVisibility(4);
                    this.bottomTextView.setVisibility(4);
                    this.bottomButton.setVisibility(4);
                }
                this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                this.fragmentView.setTag(Theme.key_windowBackgroundGray);
                return;
            }
            RecyclerListView recyclerListView2 = this.listView;
            if (recyclerListView2 != null) {
                recyclerListView2.setEmptyView(null);
                this.listView.setVisibility(4);
                this.scrollView.setVisibility(0);
                this.emptyView.setVisibility(4);
            }
            if (this.passwordEditText != null) {
                this.doneItem.setVisibility(0);
                this.passwordEditText.setVisibility(0);
                this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                this.fragmentView.setTag(Theme.key_windowBackgroundWhite);
                this.titleTextView.setVisibility(0);
                this.bottomButton.setVisibility(0);
                this.bottomTextView.setVisibility(4);
                this.bottomButton.setText(LocaleController.getString("ForgotPassword", R.string.ForgotPassword));
                this.passwordEditText.setHint("");
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$1vMtfkOq4SEHoSbrmMvszDHnmws
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$updateRows$16$TwoStepVerificationActivity();
                    }
                }, 200L);
            }
        }
    }

    public /* synthetic */ void lambda$updateRows$16$TwoStepVerificationActivity() {
        EditTextBoldCursor editTextBoldCursor;
        if (!isFinishing() && !this.destroyed && (editTextBoldCursor = this.passwordEditText) != null) {
            editTextBoldCursor.requestFocus();
            AndroidUtilities.showKeyboard(this.passwordEditText);
        }
    }

    private void showDoneProgress(final boolean show) {
        AnimatorSet animatorSet = this.doneItemAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.doneItemAnimation = new AnimatorSet();
        if (show) {
            this.progressView.setVisibility(0);
            this.doneItem.setEnabled(false);
            this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.doneItem.getContentView(), "scaleX", 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "scaleY", 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "alpha", 0.0f), ObjectAnimator.ofFloat(this.progressView, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.progressView, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.progressView, "alpha", 1.0f));
        } else {
            this.doneItem.getContentView().setVisibility(0);
            this.doneItem.setEnabled(true);
            this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.progressView, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.progressView, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.progressView, "alpha", 0.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "scaleX", 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "scaleY", 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "alpha", 1.0f));
        }
        this.doneItemAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.TwoStepVerificationActivity.4
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (TwoStepVerificationActivity.this.doneItemAnimation != null && TwoStepVerificationActivity.this.doneItemAnimation.equals(animation)) {
                    if (!show) {
                        TwoStepVerificationActivity.this.progressView.setVisibility(4);
                    } else {
                        TwoStepVerificationActivity.this.doneItem.getContentView().setVisibility(4);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (TwoStepVerificationActivity.this.doneItemAnimation != null && TwoStepVerificationActivity.this.doneItemAnimation.equals(animation)) {
                    TwoStepVerificationActivity.this.doneItemAnimation = null;
                }
            }
        });
        this.doneItemAnimation.setDuration(150L);
        this.doneItemAnimation.start();
    }

    private void needShowProgress() {
        if (getParentActivity() == null || getParentActivity().isFinishing() || this.progressDialog != null) {
            return;
        }
        AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
        this.progressDialog = alertDialog;
        alertDialog.setCanCancel(false);
        this.progressDialog.show();
    }

    protected void needHideProgress() {
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog == null) {
            return;
        }
        try {
            alertDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        this.progressDialog = null;
    }

    private boolean isValidEmail(String text) {
        if (text == null || text.length() < 3) {
            return false;
        }
        int dot = text.lastIndexOf(46);
        int dog = text.lastIndexOf(64);
        return dog >= 0 && dot >= dog;
    }

    private void showAlertWithText(String title, String text) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.setTitle(title);
        builder.setMessage(text);
        showDialog(builder.create());
    }

    private void setNewPassword(final boolean clear) {
        TLRPC.TL_account_password tL_account_password;
        if (clear && this.waitingForEmail && this.currentPassword.has_password) {
            needShowProgress();
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(new TLRPC.TL_account_cancelPasswordEmail(), new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$WYhU63FwzoXbne5m3NnL6bId53w
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$setNewPassword$18$TwoStepVerificationActivity(tLObject, tL_error);
                }
            });
            return;
        }
        final String password = this.firstPassword;
        final TLRPC.TL_account_updatePasswordSettings req = new TLRPC.TL_account_updatePasswordSettings();
        byte[] bArr = this.currentPasswordHash;
        if (bArr == null || bArr.length == 0) {
            req.password = new TLRPC.TL_inputCheckPasswordEmpty();
        }
        req.new_settings = new TLRPC.TL_account_passwordInputSettings();
        if (clear) {
            UserConfig.getInstance(this.currentAccount).resetSavedPassword();
            this.currentSecret = null;
            if (this.waitingForEmail) {
                req.new_settings.flags = 2;
                req.new_settings.email = "";
                req.password = new TLRPC.TL_inputCheckPasswordEmpty();
            } else {
                req.new_settings.flags = 3;
                req.new_settings.hint = "";
                req.new_settings.new_password_hash = new byte[0];
                req.new_settings.new_algo = new TLRPC.TL_passwordKdfAlgoUnknown();
                req.new_settings.email = "";
            }
        } else {
            if (this.hint == null && (tL_account_password = this.currentPassword) != null) {
                this.hint = tL_account_password.hint;
            }
            if (this.hint == null) {
                this.hint = "";
            }
            if (password != null) {
                req.new_settings.flags |= 1;
                req.new_settings.hint = this.hint;
                req.new_settings.new_algo = this.currentPassword.new_algo;
            }
            if (this.email.length() > 0) {
                TLRPC.TL_account_passwordInputSettings tL_account_passwordInputSettings = req.new_settings;
                tL_account_passwordInputSettings.flags = 2 | tL_account_passwordInputSettings.flags;
                req.new_settings.email = this.email.trim();
            }
        }
        needShowProgress();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$Hw8VfssAD1RHPaTeeVHbY5wdCa4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setNewPassword$25$TwoStepVerificationActivity(req, clear, password);
            }
        });
    }

    public /* synthetic */ void lambda$setNewPassword$18$TwoStepVerificationActivity(TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$bpv_peaxljpNxXDnlmD0JBoZE9o
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$17$TwoStepVerificationActivity(error);
            }
        });
    }

    public /* synthetic */ void lambda$null$17$TwoStepVerificationActivity(TLRPC.TL_error error) {
        needHideProgress();
        if (error == null) {
            loadPasswordInfo(false);
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.didRemoveTwoStepPassword, new Object[0]);
            updateRows();
        }
    }

    public /* synthetic */ void lambda$setNewPassword$25$TwoStepVerificationActivity(final TLRPC.TL_account_updatePasswordSettings req, final boolean clear, final String password) {
        byte[] newPasswordBytes;
        byte[] newPasswordHash;
        byte[] bArr;
        if (req.password == null) {
            req.password = getNewSrpPassword();
        }
        if (!clear && password != null) {
            byte[] newPasswordBytes2 = AndroidUtilities.getStringBytes(password);
            if (this.currentPassword.new_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
                TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) this.currentPassword.new_algo;
                byte[] newPasswordHash2 = SRPHelper.getX(newPasswordBytes2, algo);
                newPasswordBytes = newPasswordBytes2;
                newPasswordHash = newPasswordHash2;
            } else {
                newPasswordBytes = newPasswordBytes2;
                newPasswordHash = null;
            }
        } else {
            newPasswordBytes = null;
            newPasswordHash = null;
        }
        final byte[] bArr2 = newPasswordHash;
        RequestDelegate requestDelegate = new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$oa-gXJ1ToNPN1rJIJGO2jHZJUrU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$24$TwoStepVerificationActivity(clear, bArr2, req, password, tLObject, tL_error);
            }
        };
        if (!clear) {
            if (password != null && (bArr = this.currentSecret) != null && bArr.length == 32 && (this.currentPassword.new_secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000)) {
                TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000 newAlgo = (TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) this.currentPassword.new_secure_algo;
                byte[] passwordHash = Utilities.computePBKDF2(newPasswordBytes, newAlgo.salt);
                byte[] key = new byte[32];
                System.arraycopy(passwordHash, 0, key, 0, 32);
                byte[] iv = new byte[16];
                System.arraycopy(passwordHash, 32, iv, 0, 16);
                byte[] encryptedSecret = new byte[32];
                System.arraycopy(this.currentSecret, 0, encryptedSecret, 0, 32);
                Utilities.aesCbcEncryptionByteArraySafe(encryptedSecret, key, iv, 0, encryptedSecret.length, 0, 1);
                req.new_settings.new_secure_settings = new TLRPC.TL_secureSecretSettings();
                req.new_settings.new_secure_settings.secure_algo = newAlgo;
                req.new_settings.new_secure_settings.secure_secret = encryptedSecret;
                req.new_settings.new_secure_settings.secure_secret_id = this.currentSecretId;
                req.new_settings.flags |= 4;
            }
            if (this.currentPassword.new_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
                if (password != null) {
                    TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo2 = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) this.currentPassword.new_algo;
                    req.new_settings.new_password_hash = SRPHelper.getVBytes(newPasswordBytes, algo2);
                    if (req.new_settings.new_password_hash == null) {
                        TLRPC.TL_error error = new TLRPC.TL_error();
                        error.text = "ALGO_INVALID";
                        requestDelegate.run(null, error);
                    }
                }
                ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, requestDelegate, 10);
                return;
            }
            TLRPC.TL_error error2 = new TLRPC.TL_error();
            error2.text = "PASSWORD_HASH_INVALID";
            requestDelegate.run(null, error2);
            return;
        }
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, requestDelegate, 10);
    }

    public /* synthetic */ void lambda$null$24$TwoStepVerificationActivity(final boolean clear, final byte[] newPasswordHash, final TLRPC.TL_account_updatePasswordSettings req, final String password, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$3gv3E3iu02Re28ITNb4GzI9pgZE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$23$TwoStepVerificationActivity(error, clear, response, newPasswordHash, req, password);
            }
        });
    }

    public /* synthetic */ void lambda$null$23$TwoStepVerificationActivity(TLRPC.TL_error error, final boolean clear, TLObject response, final byte[] newPasswordHash, final TLRPC.TL_account_updatePasswordSettings req, String password) {
        String timeString;
        TLRPC.TL_account_password tL_account_password;
        if (error != null && "SRP_ID_INVALID".equals(error.text)) {
            TLRPC.TL_account_getPassword getPasswordReq = new TLRPC.TL_account_getPassword();
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(getPasswordReq, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$ymUmAuckALdXDPon5VQPeISCVSo
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$20$TwoStepVerificationActivity(clear, tLObject, tL_error);
                }
            }, 8);
            return;
        }
        needHideProgress();
        if (error == null && (response instanceof TLRPC.TL_boolTrue)) {
            if (clear) {
                this.currentPassword = null;
                this.currentPasswordHash = new byte[0];
                loadPasswordInfo(false);
                NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.didRemoveTwoStepPassword, new Object[0]);
                updateRows();
                return;
            }
            if (getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$VoT0xR2LS6c8yAPX7qCq8jKSB-E
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$21$TwoStepVerificationActivity(newPasswordHash, req, dialogInterface, i);
                }
            });
            if (password == null && (tL_account_password = this.currentPassword) != null && tL_account_password.has_password) {
                builder.setMessage(LocaleController.getString("YourEmailSuccessText", R.string.YourEmailSuccessText));
            } else {
                builder.setMessage(LocaleController.getString("YourPasswordSuccessText", R.string.YourPasswordSuccessText));
            }
            builder.setTitle(LocaleController.getString("YourPasswordSuccess", R.string.YourPasswordSuccess));
            Dialog dialog = showDialog(builder.create());
            if (dialog != null) {
                dialog.setCanceledOnTouchOutside(false);
                dialog.setCancelable(false);
                return;
            }
            return;
        }
        if (error != null) {
            if ("EMAIL_UNCONFIRMED".equals(error.text) || error.text.startsWith("EMAIL_UNCONFIRMED_")) {
                NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.didSetTwoStepPassword, new Object[0]);
                AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
                builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$IV7BrPznPR3rJ3QRqwNqJpmopgc
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$22$TwoStepVerificationActivity(newPasswordHash, req, dialogInterface, i);
                    }
                });
                builder2.setMessage(LocaleController.getString("YourEmailAlmostThereText", R.string.YourEmailAlmostThereText));
                builder2.setTitle(LocaleController.getString("YourEmailAlmostThere", R.string.YourEmailAlmostThere));
                Dialog dialog2 = showDialog(builder2.create());
                if (dialog2 != null) {
                    dialog2.setCanceledOnTouchOutside(false);
                    dialog2.setCancelable(false);
                    return;
                }
                return;
            }
            if ("EMAIL_INVALID".equals(error.text)) {
                showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("PasswordEmailInvalid", R.string.PasswordEmailInvalid));
                return;
            }
            if (error.text.startsWith("FLOOD_WAIT")) {
                int time = Utilities.parseInt(error.text).intValue();
                if (time < 60) {
                    timeString = LocaleController.formatPluralString("Seconds", time);
                } else {
                    timeString = LocaleController.formatPluralString("Minutes", time / 60);
                }
                showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
                return;
            }
            showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
        }
    }

    public /* synthetic */ void lambda$null$20$TwoStepVerificationActivity(final boolean clear, final TLObject response2, final TLRPC.TL_error error2) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$ioL7idIcluxdmMyA4cRSbKVGkNk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$19$TwoStepVerificationActivity(error2, response2, clear);
            }
        });
    }

    public /* synthetic */ void lambda$null$19$TwoStepVerificationActivity(TLRPC.TL_error error2, TLObject response2, boolean clear) {
        if (error2 == null) {
            TLRPC.TL_account_password tL_account_password = (TLRPC.TL_account_password) response2;
            this.currentPassword = tL_account_password;
            initPasswordNewAlgo(tL_account_password);
            setNewPassword(clear);
        }
    }

    public /* synthetic */ void lambda$null$21$TwoStepVerificationActivity(byte[] newPasswordHash, TLRPC.TL_account_updatePasswordSettings req, DialogInterface dialogInterface, int i) {
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.didSetTwoStepPassword, newPasswordHash, req.new_settings.new_algo, this.currentPassword.new_secure_algo, this.currentPassword.secure_random, this.email, this.hint, null, this.firstPassword);
        finishFragment();
    }

    public /* synthetic */ void lambda$null$22$TwoStepVerificationActivity(byte[] newPasswordHash, TLRPC.TL_account_updatePasswordSettings req, DialogInterface dialogInterface, int i) {
        if (this.closeAfterSet) {
            TwoStepVerificationActivity activity = new TwoStepVerificationActivity(this.currentAccount, 0);
            activity.setCloseAfterSet(true);
            this.parentLayout.addFragmentToStack(activity, this.parentLayout.fragmentsStack.size() - 1);
        }
        NotificationCenter notificationCenter = NotificationCenter.getInstance(this.currentAccount);
        int i2 = NotificationCenter.didSetTwoStepPassword;
        String str = this.email;
        notificationCenter.postNotificationName(i2, newPasswordHash, req.new_settings.new_algo, this.currentPassword.new_secure_algo, this.currentPassword.secure_random, str, this.hint, str, this.firstPassword);
        finishFragment();
    }

    protected TLRPC.TL_inputCheckPasswordSRP getNewSrpPassword() {
        if (this.currentPassword.current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
            TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) this.currentPassword.current_algo;
            return SRPHelper.startCheck(this.currentPasswordHash, this.currentPassword.srp_id, this.currentPassword.srp_B, algo);
        }
        return null;
    }

    private boolean checkSecretValues(byte[] passwordBytes, TLRPC.TL_account_passwordSettings passwordSettings) {
        byte[] passwordHash;
        if (passwordSettings.secure_settings != null) {
            this.currentSecret = passwordSettings.secure_settings.secure_secret;
            if (passwordSettings.secure_settings.secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) {
                passwordHash = Utilities.computePBKDF2(passwordBytes, ((TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) passwordSettings.secure_settings.secure_algo).salt);
            } else {
                if (!(passwordSettings.secure_settings.secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoSHA512)) {
                    return false;
                }
                TLRPC.TL_securePasswordKdfAlgoSHA512 algo = (TLRPC.TL_securePasswordKdfAlgoSHA512) passwordSettings.secure_settings.secure_algo;
                passwordHash = Utilities.computeSHA512(algo.salt, passwordBytes, algo.salt);
            }
            this.currentSecretId = passwordSettings.secure_settings.secure_secret_id;
            byte[] key = new byte[32];
            System.arraycopy(passwordHash, 0, key, 0, 32);
            byte[] iv = new byte[16];
            System.arraycopy(passwordHash, 32, iv, 0, 16);
            byte[] bArr = this.currentSecret;
            Utilities.aesCbcEncryptionByteArraySafe(bArr, key, iv, 0, bArr.length, 0, 0);
            if (!PassportActivity.checkSecret(passwordSettings.secure_settings.secure_secret, Long.valueOf(passwordSettings.secure_settings.secure_secret_id))) {
                TLRPC.TL_account_updatePasswordSettings req = new TLRPC.TL_account_updatePasswordSettings();
                req.password = getNewSrpPassword();
                req.new_settings = new TLRPC.TL_account_passwordInputSettings();
                req.new_settings.new_secure_settings = new TLRPC.TL_secureSecretSettings();
                req.new_settings.new_secure_settings.secure_secret = new byte[0];
                req.new_settings.new_secure_settings.secure_algo = new TLRPC.TL_securePasswordKdfAlgoUnknown();
                req.new_settings.new_secure_settings.secure_secret_id = 0L;
                req.new_settings.flags |= 4;
                ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$rMp3SDsMaBkQaRVguGuapwlD4NI
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        TwoStepVerificationActivity.lambda$checkSecretValues$26(tLObject, tL_error);
                    }
                });
                this.currentSecret = null;
                this.currentSecretId = 0L;
                return true;
            }
            return true;
        }
        this.currentSecret = null;
        this.currentSecretId = 0L;
        return true;
    }

    static /* synthetic */ void lambda$checkSecretValues$26(TLObject response, TLRPC.TL_error error) {
    }

    private static byte[] getBigIntegerBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 256) {
            byte[] correctedAuth = new byte[256];
            System.arraycopy(bytes, 1, correctedAuth, 0, 256);
            return correctedAuth;
        }
        return bytes;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processDone() {
        int i = this.type;
        if (i == 0) {
            if (!this.passwordEntered) {
                String oldPassword = this.passwordEditText.getText().toString();
                if (oldPassword.length() == 0) {
                    onFieldError(this.passwordEditText, false);
                    return;
                }
                final byte[] oldPasswordBytes = AndroidUtilities.getStringBytes(oldPassword);
                needShowProgress();
                Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$saGKwvcNdXrJOTN3DAPu1IaCTcw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$processDone$33$TwoStepVerificationActivity(oldPasswordBytes);
                    }
                });
                return;
            }
            if (this.waitingForEmail && this.currentPassword != null) {
                if (this.codeFieldCell.length() == 0) {
                    onFieldError(this.codeFieldCell.getTextView(), false);
                    return;
                } else {
                    sendEmailConfirm(this.codeFieldCell.getText());
                    showDoneProgress(true);
                    return;
                }
            }
            return;
        }
        if (i == 1) {
            int i2 = this.passwordSetState;
            if (i2 == 0) {
                if (this.passwordEditText.getText().length() == 0) {
                    onFieldError(this.passwordEditText, false);
                    return;
                }
                this.titleTextView.setText(LocaleController.getString("ReEnterYourPasscode", R.string.ReEnterYourPasscode));
                this.firstPassword = this.passwordEditText.getText().toString();
                setPasswordSetState(1);
                return;
            }
            if (i2 != 1) {
                if (i2 == 2) {
                    String string = this.passwordEditText.getText().toString();
                    this.hint = string;
                    if (string.toLowerCase().equals(this.firstPassword.toLowerCase())) {
                        ToastUtils.show(R.string.PasswordAsHintError);
                        onFieldError(this.passwordEditText, false);
                        return;
                    } else if (!this.currentPassword.has_recovery) {
                        setPasswordSetState(3);
                        return;
                    } else {
                        this.email = "";
                        setNewPassword(false);
                        return;
                    }
                }
                if (i2 == 3) {
                    String string2 = this.passwordEditText.getText().toString();
                    this.email = string2;
                    if (!isValidEmail(string2)) {
                        onFieldError(this.passwordEditText, false);
                        return;
                    } else {
                        setNewPassword(false);
                        return;
                    }
                }
                if (i2 == 4) {
                    String code = this.passwordEditText.getText().toString();
                    if (code.length() == 0) {
                        onFieldError(this.passwordEditText, false);
                        return;
                    }
                    TLRPC.TL_auth_recoverPassword req = new TLRPC.TL_auth_recoverPassword();
                    req.code = code;
                    ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$Lb_a-4uzryiw8E8Du17ORce97rY
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$processDone$36$TwoStepVerificationActivity(tLObject, tL_error);
                        }
                    }, 10);
                    return;
                }
                return;
            }
            if (!this.firstPassword.equals(this.passwordEditText.getText().toString())) {
                ToastUtils.show(R.string.PasswordDoNotMatch);
                onFieldError(this.passwordEditText, true);
            } else {
                setPasswordSetState(2);
            }
        }
    }

    public /* synthetic */ void lambda$processDone$33$TwoStepVerificationActivity(final byte[] oldPasswordBytes) {
        final byte[] x_bytes;
        TLRPC.TL_account_getPasswordSettings req = new TLRPC.TL_account_getPasswordSettings();
        if (this.currentPassword.current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
            TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) this.currentPassword.current_algo;
            x_bytes = SRPHelper.getX(oldPasswordBytes, algo);
        } else {
            x_bytes = null;
        }
        RequestDelegate requestDelegate = new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$ntC51QTHZ3jzE7GJ7cByUNyPUq0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$32$TwoStepVerificationActivity(oldPasswordBytes, x_bytes, tLObject, tL_error);
            }
        };
        if (this.currentPassword.current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
            TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo2 = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) this.currentPassword.current_algo;
            req.password = SRPHelper.startCheck(x_bytes, this.currentPassword.srp_id, this.currentPassword.srp_B, algo2);
            if (req.password == null) {
                TLRPC.TL_error error = new TLRPC.TL_error();
                error.text = "ALGO_INVALID";
                requestDelegate.run(null, error);
                return;
            }
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, requestDelegate, 10);
            return;
        }
        TLRPC.TL_error error2 = new TLRPC.TL_error();
        error2.text = "PASSWORD_HASH_INVALID";
        requestDelegate.run(null, error2);
    }

    public /* synthetic */ void lambda$null$32$TwoStepVerificationActivity(final byte[] oldPasswordBytes, final byte[] x_bytes, final TLObject response, final TLRPC.TL_error error) {
        if (error == null) {
            Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$CjWaTz7W-Ksxira0sMrKXaDo1qg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$28$TwoStepVerificationActivity(oldPasswordBytes, response, x_bytes);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$8c4EnlWw9FMhUd7jd4zooTb83yM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$31$TwoStepVerificationActivity(error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$28$TwoStepVerificationActivity(byte[] oldPasswordBytes, TLObject response, final byte[] x_bytes) {
        final boolean secretOk = checkSecretValues(oldPasswordBytes, (TLRPC.TL_account_passwordSettings) response);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$Xkd2NSZ-zTtf8HCFIr0ShIflk1c
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$27$TwoStepVerificationActivity(secretOk, x_bytes);
            }
        });
    }

    public /* synthetic */ void lambda$null$27$TwoStepVerificationActivity(boolean secretOk, byte[] x_bytes) {
        if (this.delegate == null || !secretOk) {
            needHideProgress();
        }
        if (!secretOk) {
            AlertsCreator.showUpdateAppAlert(getParentActivity(), LocaleController.getString("UpdateAppAlert", R.string.UpdateAppAlert), true);
            return;
        }
        this.currentPasswordHash = x_bytes;
        this.passwordEntered = true;
        AndroidUtilities.hideKeyboard(this.passwordEditText);
        TwoStepVerificationActivityDelegate twoStepVerificationActivityDelegate = this.delegate;
        if (twoStepVerificationActivityDelegate != null) {
            twoStepVerificationActivityDelegate.didEnterPassword(getNewSrpPassword());
        } else {
            updateRows();
        }
    }

    public /* synthetic */ void lambda$null$31$TwoStepVerificationActivity(TLRPC.TL_error error) {
        String timeString;
        if ("SRP_ID_INVALID".equals(error.text)) {
            TLRPC.TL_account_getPassword getPasswordReq = new TLRPC.TL_account_getPassword();
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(getPasswordReq, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$79qDANWl7eLa4T3msd1aYL6MnlQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$30$TwoStepVerificationActivity(tLObject, tL_error);
                }
            }, 8);
            return;
        }
        needHideProgress();
        if ("PASSWORD_HASH_INVALID".equals(error.text)) {
            onFieldError(this.passwordEditText, true);
            return;
        }
        if (error.text.startsWith("FLOOD_WAIT")) {
            int time = Utilities.parseInt(error.text).intValue();
            if (time < 60) {
                timeString = LocaleController.formatPluralString("Seconds", time);
            } else {
                timeString = LocaleController.formatPluralString("Minutes", time / 60);
            }
            showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
            return;
        }
        showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
    }

    public /* synthetic */ void lambda$null$30$TwoStepVerificationActivity(final TLObject response2, final TLRPC.TL_error error2) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$n5jVbSxshs-4j_bVE6HXthQ-xuo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$29$TwoStepVerificationActivity(error2, response2);
            }
        });
    }

    public /* synthetic */ void lambda$null$29$TwoStepVerificationActivity(TLRPC.TL_error error2, TLObject response2) {
        if (error2 == null) {
            TLRPC.TL_account_password tL_account_password = (TLRPC.TL_account_password) response2;
            this.currentPassword = tL_account_password;
            initPasswordNewAlgo(tL_account_password);
            processDone();
        }
    }

    public /* synthetic */ void lambda$processDone$36$TwoStepVerificationActivity(TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$a9rMFonObMGB7Im29cGTCaOOWPU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$35$TwoStepVerificationActivity(error);
            }
        });
    }

    public /* synthetic */ void lambda$null$35$TwoStepVerificationActivity(TLRPC.TL_error error) {
        String timeString;
        if (error == null) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$myAeUm0ey67ylIrT4FnhT3TUHRg
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$34$TwoStepVerificationActivity(dialogInterface, i);
                }
            });
            builder.setMessage(LocaleController.getString("PasswordReset", R.string.PasswordReset));
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            Dialog dialog = showDialog(builder.create());
            if (dialog != null) {
                dialog.setCanceledOnTouchOutside(false);
                dialog.setCancelable(false);
                return;
            }
            return;
        }
        if (error.text.startsWith("CODE_INVALID")) {
            onFieldError(this.passwordEditText, true);
            return;
        }
        if (error.text.startsWith("FLOOD_WAIT")) {
            int time = Utilities.parseInt(error.text).intValue();
            if (time < 60) {
                timeString = LocaleController.formatPluralString("Seconds", time);
            } else {
                timeString = LocaleController.formatPluralString("Minutes", time / 60);
            }
            showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
            return;
        }
        showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
    }

    public /* synthetic */ void lambda$null$34$TwoStepVerificationActivity(DialogInterface dialogInterface, int i) {
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.didSetTwoStepPassword, new Object[0]);
        finishFragment();
    }

    private void sendEmailConfirm(String code) {
        TLRPC.TL_account_confirmPasswordEmail req = new TLRPC.TL_account_confirmPasswordEmail();
        req.code = code;
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$_TFWV2ddUPYcezLCB6xb2hUs8aQ
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$sendEmailConfirm$39$TwoStepVerificationActivity(tLObject, tL_error);
            }
        }, 10);
    }

    public /* synthetic */ void lambda$sendEmailConfirm$39$TwoStepVerificationActivity(TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$W7VXZSvUEX_E25TnC5kod7b-cuI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$38$TwoStepVerificationActivity(error);
            }
        });
    }

    public /* synthetic */ void lambda$null$38$TwoStepVerificationActivity(TLRPC.TL_error error) {
        String timeString;
        if (this.type == 0 && this.waitingForEmail) {
            showDoneProgress(false);
        }
        if (error == null) {
            if (getParentActivity() == null) {
                return;
            }
            Runnable runnable = this.shortPollRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.shortPollRunnable = null;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$TwoStepVerificationActivity$zw0f9j12Femj5QKMzk-ZWmo-sco
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$37$TwoStepVerificationActivity(dialogInterface, i);
                }
            });
            TLRPC.TL_account_password tL_account_password = this.currentPassword;
            if (tL_account_password != null && tL_account_password.has_password) {
                builder.setMessage(LocaleController.getString("YourEmailSuccessText", R.string.YourEmailSuccessText));
            } else {
                builder.setMessage(LocaleController.getString("YourPasswordSuccessText", R.string.YourPasswordSuccessText));
            }
            builder.setTitle(LocaleController.getString("YourPasswordSuccess", R.string.YourPasswordSuccess));
            Dialog dialog = showDialog(builder.create());
            if (dialog != null) {
                dialog.setCanceledOnTouchOutside(false);
                dialog.setCancelable(false);
                return;
            }
            return;
        }
        if (error.text.startsWith("CODE_INVALID")) {
            onFieldError(this.waitingForEmail ? this.codeFieldCell.getTextView() : this.passwordEditText, true);
            return;
        }
        if (error.text.startsWith("FLOOD_WAIT")) {
            int time = Utilities.parseInt(error.text).intValue();
            if (time < 60) {
                timeString = LocaleController.formatPluralString("Seconds", time);
            } else {
                timeString = LocaleController.formatPluralString("Minutes", time / 60);
            }
            showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
            return;
        }
        showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
    }

    public /* synthetic */ void lambda$null$37$TwoStepVerificationActivity(DialogInterface dialogInterface, int i) {
        if (this.type == 0) {
            loadPasswordInfo(false);
            this.doneItem.setVisibility(8);
        } else {
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.didSetTwoStepPassword, this.currentPasswordHash, this.currentPassword.new_algo, this.currentPassword.new_secure_algo, this.currentPassword.secure_random, this.email, this.hint, null, this.firstPassword);
            finishFragment();
        }
    }

    private void onFieldError(TextView field, boolean clear) {
        if (getParentActivity() == null) {
            return;
        }
        Vibrator v = (Vibrator) getParentActivity().getSystemService("vibrator");
        if (v != null) {
            v.vibrate(200L);
        }
        if (clear) {
            field.setText("");
        }
        AndroidUtilities.shakeView(field, 2.0f, 0);
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (TwoStepVerificationActivity.this.loading || TwoStepVerificationActivity.this.currentPassword == null) {
                return 0;
            }
            return TwoStepVerificationActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new TextSettingsCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType != 1) {
                view = TwoStepVerificationActivity.this.codeFieldCell;
                if (view.getParent() != null) {
                    ((ViewGroup) view.getParent()).removeView(view);
                }
            } else {
                view = new TextInfoPrivacyCell(this.mContext);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    TextInfoPrivacyCell privacyCell = (TextInfoPrivacyCell) holder.itemView;
                    if (position != TwoStepVerificationActivity.this.setPasswordDetailRow) {
                        if (position != TwoStepVerificationActivity.this.shadowRow) {
                            if (position == TwoStepVerificationActivity.this.passwordSetupDetailRow) {
                                if (TwoStepVerificationActivity.this.currentPassword == null || !TwoStepVerificationActivity.this.currentPassword.has_password) {
                                    Object[] objArr = new Object[1];
                                    objArr[0] = TwoStepVerificationActivity.this.currentPassword.email_unconfirmed_pattern != null ? TwoStepVerificationActivity.this.currentPassword.email_unconfirmed_pattern : "";
                                    privacyCell.setText(LocaleController.formatString("EmailPasswordConfirmText2", R.string.EmailPasswordConfirmText2, objArr));
                                } else {
                                    Object[] objArr2 = new Object[1];
                                    objArr2[0] = TwoStepVerificationActivity.this.currentPassword.email_unconfirmed_pattern != null ? TwoStepVerificationActivity.this.currentPassword.email_unconfirmed_pattern : "";
                                    privacyCell.setText(LocaleController.formatString("EmailPasswordConfirmText3", R.string.EmailPasswordConfirmText3, objArr2));
                                }
                                privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_top, Theme.key_windowBackgroundGrayShadow));
                                return;
                            }
                            if (position == TwoStepVerificationActivity.this.passwordEnabledDetailRow) {
                                privacyCell.setText(LocaleController.getString("EnabledPasswordText", R.string.EnabledPasswordText));
                                privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                                return;
                            }
                            return;
                        }
                        privacyCell.setText("");
                        privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                        return;
                    }
                    privacyCell.setText(LocaleController.getString("SetAdditionalPasswordInfo", R.string.SetAdditionalPasswordInfo));
                    privacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    return;
                }
                return;
            }
            TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
            textCell.setTag(Theme.key_windowBackgroundWhiteBlackText);
            textCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            if (position != TwoStepVerificationActivity.this.changePasswordRow) {
                if (position != TwoStepVerificationActivity.this.setPasswordRow) {
                    if (position != TwoStepVerificationActivity.this.turnPasswordOffRow) {
                        if (position == TwoStepVerificationActivity.this.changeRecoveryEmailRow) {
                            textCell.setText(LocaleController.getString("ChangeRecoveryEmail", R.string.ChangeRecoveryEmail), TwoStepVerificationActivity.this.abortPasswordRow != -1);
                            return;
                        }
                        if (position != TwoStepVerificationActivity.this.resendCodeRow) {
                            if (position != TwoStepVerificationActivity.this.setRecoveryEmailRow) {
                                if (position == TwoStepVerificationActivity.this.abortPasswordRow) {
                                    textCell.setTag(Theme.key_windowBackgroundWhiteRedText3);
                                    textCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText3));
                                    if (TwoStepVerificationActivity.this.currentPassword != null && TwoStepVerificationActivity.this.currentPassword.has_password) {
                                        textCell.setText(LocaleController.getString("AbortEmail", R.string.AbortEmail), false);
                                        return;
                                    } else {
                                        textCell.setText(LocaleController.getString("AbortPassword", R.string.AbortPassword), false);
                                        return;
                                    }
                                }
                                return;
                            }
                            textCell.setText(LocaleController.getString("SetRecoveryEmail", R.string.SetRecoveryEmail), false);
                            return;
                        }
                        textCell.setText(LocaleController.getString("ResendCode", R.string.ResendCode), true);
                        return;
                    }
                    textCell.setText(LocaleController.getString("TurnPasswordOff", R.string.TurnPasswordOff), true);
                    return;
                }
                textCell.setText(LocaleController.getString("SetAdditionalPassword", R.string.SetAdditionalPassword), true);
                return;
            }
            textCell.setText(LocaleController.getString("ChangePassword", R.string.ChangePassword), true);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != TwoStepVerificationActivity.this.setPasswordDetailRow && position != TwoStepVerificationActivity.this.shadowRow && position != TwoStepVerificationActivity.this.passwordSetupDetailRow && position != TwoStepVerificationActivity.this.passwordEnabledDetailRow) {
                if (position == TwoStepVerificationActivity.this.passwordCodeFieldRow) {
                    return 2;
                }
                return 0;
            }
            return 1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class, EditTextSettingsCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_CHECKTAG | ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteRedText3), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{EditTextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_HINTTEXTCOLOR, new Class[]{EditTextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.titleTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6), new ThemeDescription(this.bottomTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6), new ThemeDescription(this.bottomButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4), new ThemeDescription(this.passwordEditText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.passwordEditText, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.passwordEditText, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField), new ThemeDescription(this.passwordEditText, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated)};
    }
}
