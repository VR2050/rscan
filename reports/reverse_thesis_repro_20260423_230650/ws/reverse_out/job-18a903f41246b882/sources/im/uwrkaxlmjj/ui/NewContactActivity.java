package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Vibrator;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.AdapterView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.CountrySelectActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.HintEditText;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.ArrayList;
import java.util.HashMap;
import kotlin.text.Typography;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class NewContactActivity extends BaseFragment implements AdapterView.OnItemSelectedListener {
    private static final int done_button = 1;
    private AvatarDrawable avatarDrawable;
    private BackupImageView avatarImage;
    private EditTextBoldCursor codeField;
    private TextView countryButton;
    private int countryState;
    private boolean donePressed;
    private ActionBarMenuItem editDoneItem;
    private AnimatorSet editDoneItemAnimation;
    private ContextProgressView editDoneItemProgress;
    private EditTextBoldCursor firstNameField;
    private boolean ignoreOnPhoneChange;
    private boolean ignoreOnTextChange;
    private boolean ignoreSelection;
    private String initialPhoneNumber;
    private EditTextBoldCursor lastNameField;
    private View lineView;
    private HintEditText phoneField;
    private TextView textView;
    private ArrayList<String> countriesArray = new ArrayList<>();
    private HashMap<String, String> countriesMap = new HashMap<>();
    private HashMap<String, String> codesMap = new HashMap<>();
    private HashMap<String, String> phoneFormatMap = new HashMap<>();

    /* JADX WARN: Removed duplicated region for block: B:16:0x044b  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0455  */
    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.view.View createView(android.content.Context r26) {
        /*
            Method dump skipped, instruction units count: 1203
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.NewContactActivity.createView(android.content.Context):android.view.View");
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.NewContactActivity$1, reason: invalid class name */
    class AnonymousClass1 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass1() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == -1) {
                NewContactActivity.this.finishFragment();
                return;
            }
            if (id == 1 && !NewContactActivity.this.donePressed) {
                if (NewContactActivity.this.firstNameField.length() != 0) {
                    if (NewContactActivity.this.codeField.length() != 0) {
                        if (NewContactActivity.this.phoneField.length() != 0) {
                            NewContactActivity.this.donePressed = true;
                            NewContactActivity.this.showEditDoneProgress(true, true);
                            final TLRPC.TL_contacts_importContacts req = new TLRPC.TL_contacts_importContacts();
                            final TLRPC.TL_inputPhoneContact inputPhoneContact = new TLRPC.TL_inputPhoneContact();
                            inputPhoneContact.first_name = NewContactActivity.this.firstNameField.getText().toString();
                            inputPhoneContact.last_name = NewContactActivity.this.lastNameField.getText().toString();
                            inputPhoneContact.phone = Marker.ANY_NON_NULL_MARKER + NewContactActivity.this.codeField.getText().toString() + NewContactActivity.this.phoneField.getText().toString();
                            req.contacts.add(inputPhoneContact);
                            int reqId = ConnectionsManager.getInstance(NewContactActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NewContactActivity$1$mdrGViDHr90kilNqW0sxDnOSeEU
                                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                    this.f$0.lambda$onItemClick$2$NewContactActivity$1(inputPhoneContact, req, tLObject, tL_error);
                                }
                            }, 2);
                            ConnectionsManager.getInstance(NewContactActivity.this.currentAccount).bindRequestToGuid(reqId, NewContactActivity.this.classGuid);
                            return;
                        }
                        Vibrator v = (Vibrator) NewContactActivity.this.getParentActivity().getSystemService("vibrator");
                        if (v != null) {
                            v.vibrate(200L);
                        }
                        AndroidUtilities.shakeView(NewContactActivity.this.phoneField, 2.0f, 0);
                        return;
                    }
                    Vibrator v2 = (Vibrator) NewContactActivity.this.getParentActivity().getSystemService("vibrator");
                    if (v2 != null) {
                        v2.vibrate(200L);
                    }
                    AndroidUtilities.shakeView(NewContactActivity.this.codeField, 2.0f, 0);
                    return;
                }
                Vibrator v3 = (Vibrator) NewContactActivity.this.getParentActivity().getSystemService("vibrator");
                if (v3 != null) {
                    v3.vibrate(200L);
                }
                AndroidUtilities.shakeView(NewContactActivity.this.firstNameField, 2.0f, 0);
            }
        }

        public /* synthetic */ void lambda$onItemClick$2$NewContactActivity$1(final TLRPC.TL_inputPhoneContact inputPhoneContact, final TLRPC.TL_contacts_importContacts req, TLObject response, final TLRPC.TL_error error) {
            final TLRPC.TL_contacts_importedContacts res = (TLRPC.TL_contacts_importedContacts) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NewContactActivity$1$DLsdiu8HgTPNLmmyBmx5OxZtA1o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$NewContactActivity$1(res, inputPhoneContact, error, req);
                }
            });
        }

        public /* synthetic */ void lambda$null$1$NewContactActivity$1(TLRPC.TL_contacts_importedContacts res, final TLRPC.TL_inputPhoneContact inputPhoneContact, TLRPC.TL_error error, TLRPC.TL_contacts_importContacts req) {
            NewContactActivity.this.donePressed = false;
            if (res == null) {
                NewContactActivity.this.showEditDoneProgress(false, true);
                AlertsCreator.processError(NewContactActivity.this.currentAccount, error, NewContactActivity.this, req, new Object[0]);
                return;
            }
            if (!res.users.isEmpty()) {
                MessagesController.getInstance(NewContactActivity.this.currentAccount).putUsers(res.users, false);
                MessagesController.openChatOrProfileWith(res.users.get(0), null, NewContactActivity.this, 1, true);
            } else if (NewContactActivity.this.getParentActivity() != null) {
                NewContactActivity.this.showEditDoneProgress(false, true);
                AlertDialog.Builder builder = new AlertDialog.Builder(NewContactActivity.this.getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.formatString("ContactNotRegistered", R.string.ContactNotRegistered, ContactsController.formatName(inputPhoneContact.first_name, inputPhoneContact.last_name)));
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                builder.setPositiveButton(LocaleController.getString("Invite", R.string.Invite), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NewContactActivity$1$dAb6LNG-TKZWHrPblflS82txbsY
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$0$NewContactActivity$1(inputPhoneContact, dialogInterface, i);
                    }
                });
                NewContactActivity.this.showDialog(builder.create());
            }
        }

        public /* synthetic */ void lambda$null$0$NewContactActivity$1(TLRPC.TL_inputPhoneContact inputPhoneContact, DialogInterface dialog, int which) {
            try {
                Intent intent = new Intent("android.intent.action.VIEW", Uri.fromParts("sms", inputPhoneContact.phone, null));
                intent.putExtra("sms_body", ContactsController.getInstance(NewContactActivity.this.currentAccount).getInviteText(1));
                NewContactActivity.this.getParentActivity().startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ boolean lambda$createView$1$NewContactActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5) {
            this.lastNameField.requestFocus();
            EditTextBoldCursor editTextBoldCursor = this.lastNameField;
            editTextBoldCursor.setSelection(editTextBoldCursor.length());
            return true;
        }
        return false;
    }

    public /* synthetic */ boolean lambda$createView$2$NewContactActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5) {
            this.phoneField.requestFocus();
            HintEditText hintEditText = this.phoneField;
            hintEditText.setSelection(hintEditText.length());
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$createView$5$NewContactActivity(View view) {
        CountrySelectActivity fragment = new CountrySelectActivity(true);
        fragment.setCountrySelectActivityDelegate(new CountrySelectActivity.CountrySelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NewContactActivity$a-7uwbUAKG_yKOoliAUkFCU9Ccg
            @Override // im.uwrkaxlmjj.ui.CountrySelectActivity.CountrySelectActivityDelegate
            public final void didSelectCountry(CountrySelectActivity.Country country) {
                this.f$0.lambda$null$4$NewContactActivity(country);
            }
        });
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$null$4$NewContactActivity(CountrySelectActivity.Country country) {
        selectCountry(null, country);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NewContactActivity$8ouTSm7pLC3o8mu3sV6UV_qWa7w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$NewContactActivity();
            }
        }, 300L);
        this.phoneField.requestFocus();
        HintEditText hintEditText = this.phoneField;
        hintEditText.setSelection(hintEditText.length());
    }

    public /* synthetic */ void lambda$null$3$NewContactActivity() {
        AndroidUtilities.showKeyboard(this.phoneField);
    }

    public /* synthetic */ boolean lambda$createView$6$NewContactActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5) {
            this.phoneField.requestFocus();
            HintEditText hintEditText = this.phoneField;
            hintEditText.setSelection(hintEditText.length());
            return true;
        }
        return false;
    }

    public /* synthetic */ boolean lambda$createView$7$NewContactActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 6) {
            this.editDoneItem.performClick();
            return true;
        }
        return false;
    }

    public /* synthetic */ boolean lambda$createView$8$NewContactActivity(View v, int keyCode, KeyEvent event) {
        if (keyCode == 67 && this.phoneField.length() == 0) {
            this.codeField.requestFocus();
            EditTextBoldCursor editTextBoldCursor = this.codeField;
            editTextBoldCursor.setSelection(editTextBoldCursor.length());
            this.codeField.dispatchKeyEvent(event);
            return true;
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        boolean animations = preferences.getBoolean("view_animations", true);
        if (!animations) {
            this.firstNameField.requestFocus();
            AndroidUtilities.showKeyboard(this.firstNameField);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        if (isOpen) {
            this.firstNameField.requestFocus();
            AndroidUtilities.showKeyboard(this.firstNameField);
        }
    }

    public void setInitialPhoneNumber(String value) {
        this.initialPhoneNumber = value;
    }

    public void selectCountry(String name, CountrySelectActivity.Country country) {
        if (name != null) {
            int index = this.countriesArray.indexOf(name);
            if (index != -1) {
                this.ignoreOnTextChange = true;
                String code = this.countriesMap.get(name);
                this.codeField.setText(code);
                this.countryButton.setText(name);
                String hint = this.phoneFormatMap.get(code);
                this.phoneField.setHintText(hint != null ? hint.replace('X', Typography.ndash) : null);
                this.countryState = 0;
                this.ignoreOnTextChange = false;
                return;
            }
            return;
        }
        if (country != null) {
            this.ignoreOnTextChange = true;
            this.codeField.setText(country.code + "");
            if (country.phoneFormat != null) {
                this.phoneField.setHintText(country.phoneFormat != null ? country.phoneFormat.replace('X', Typography.ndash) : null);
            }
            this.countryState = 0;
            this.ignoreOnTextChange = false;
        }
    }

    @Override // android.widget.AdapterView.OnItemSelectedListener
    public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
        if (this.ignoreSelection) {
            this.ignoreSelection = false;
            return;
        }
        this.ignoreOnTextChange = true;
        String str = this.countriesArray.get(i);
        this.codeField.setText(this.countriesMap.get(str));
        this.ignoreOnTextChange = false;
    }

    @Override // android.widget.AdapterView.OnItemSelectedListener
    public void onNothingSelected(AdapterView<?> adapterView) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showEditDoneProgress(final boolean show, boolean animated) {
        AnimatorSet animatorSet = this.editDoneItemAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        if (animated) {
            this.editDoneItemAnimation = new AnimatorSet();
            if (show) {
                this.editDoneItemProgress.setVisibility(0);
                this.editDoneItem.setEnabled(false);
                this.editDoneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.editDoneItem.getContentView(), "scaleX", 0.1f), ObjectAnimator.ofFloat(this.editDoneItem.getContentView(), "scaleY", 0.1f), ObjectAnimator.ofFloat(this.editDoneItem.getContentView(), "alpha", 0.0f), ObjectAnimator.ofFloat(this.editDoneItemProgress, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.editDoneItemProgress, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.editDoneItemProgress, "alpha", 1.0f));
            } else {
                this.editDoneItem.getContentView().setVisibility(0);
                this.editDoneItem.setEnabled(true);
                this.editDoneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.editDoneItemProgress, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.editDoneItemProgress, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.editDoneItemProgress, "alpha", 0.0f), ObjectAnimator.ofFloat(this.editDoneItem.getContentView(), "scaleX", 1.0f), ObjectAnimator.ofFloat(this.editDoneItem.getContentView(), "scaleY", 1.0f), ObjectAnimator.ofFloat(this.editDoneItem.getContentView(), "alpha", 1.0f));
            }
            this.editDoneItemAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.NewContactActivity.6
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (NewContactActivity.this.editDoneItemAnimation != null && NewContactActivity.this.editDoneItemAnimation.equals(animation)) {
                        if (!show) {
                            NewContactActivity.this.editDoneItemProgress.setVisibility(4);
                        } else {
                            NewContactActivity.this.editDoneItem.getContentView().setVisibility(4);
                        }
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (NewContactActivity.this.editDoneItemAnimation != null && NewContactActivity.this.editDoneItemAnimation.equals(animation)) {
                        NewContactActivity.this.editDoneItemAnimation = null;
                    }
                }
            });
            this.editDoneItemAnimation.setDuration(150L);
            this.editDoneItemAnimation.start();
            return;
        }
        if (show) {
            this.editDoneItem.getContentView().setScaleX(0.1f);
            this.editDoneItem.getContentView().setScaleY(0.1f);
            this.editDoneItem.getContentView().setAlpha(0.0f);
            this.editDoneItemProgress.setScaleX(1.0f);
            this.editDoneItemProgress.setScaleY(1.0f);
            this.editDoneItemProgress.setAlpha(1.0f);
            this.editDoneItem.getContentView().setVisibility(4);
            this.editDoneItemProgress.setVisibility(0);
            this.editDoneItem.setEnabled(false);
            return;
        }
        this.editDoneItemProgress.setScaleX(0.1f);
        this.editDoneItemProgress.setScaleY(0.1f);
        this.editDoneItemProgress.setAlpha(0.0f);
        this.editDoneItem.getContentView().setScaleX(1.0f);
        this.editDoneItem.getContentView().setScaleY(1.0f);
        this.editDoneItem.getContentView().setAlpha(1.0f);
        this.editDoneItem.getContentView().setVisibility(0);
        this.editDoneItemProgress.setVisibility(4);
        this.editDoneItem.setEnabled(true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$NewContactActivity$o2QoDCZqeyWgCfu-VX1j73blI5I
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$9$NewContactActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.firstNameField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.firstNameField, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.firstNameField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField), new ThemeDescription(this.firstNameField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated), new ThemeDescription(this.lastNameField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.lastNameField, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.lastNameField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField), new ThemeDescription(this.lastNameField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated), new ThemeDescription(this.codeField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.codeField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField), new ThemeDescription(this.codeField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated), new ThemeDescription(this.phoneField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.phoneField, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.phoneField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField), new ThemeDescription(this.phoneField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated), new ThemeDescription(this.textView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.lineView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhiteGrayLine), new ThemeDescription(this.countryButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.editDoneItemProgress, 0, null, null, null, null, Theme.key_contextProgressInner2), new ThemeDescription(this.editDoneItemProgress, 0, null, null, null, null, Theme.key_contextProgressOuter2), new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.avatar_savedDrawable}, cellDelegate, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$9$NewContactActivity() {
        if (this.avatarImage != null) {
            this.avatarDrawable.setInfo(5, this.firstNameField.getText().toString(), this.lastNameField.getText().toString());
            this.avatarImage.invalidate();
        }
    }
}
