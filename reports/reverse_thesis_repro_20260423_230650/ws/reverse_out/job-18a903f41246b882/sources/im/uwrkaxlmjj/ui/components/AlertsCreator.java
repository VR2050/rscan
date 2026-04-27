package im.uwrkaxlmjj.ui.components;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.Html;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.URLSpan;
import android.util.Base64;
import android.util.SparseArray;
import android.view.MotionEvent;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SecretChatHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.CacheControlActivity;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.LanguageSelectActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.NotificationsCustomSettingsActivity;
import im.uwrkaxlmjj.ui.NotificationsSettingsActivity;
import im.uwrkaxlmjj.ui.ProfileNotificationsActivity;
import im.uwrkaxlmjj.ui.ReportOtherActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.AccountSelectCell;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.RadioColorCell;
import im.uwrkaxlmjj.ui.cells.TextColorCell;
import im.uwrkaxlmjj.ui.components.NumberPicker;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class AlertsCreator {

    public interface AccountSelectDelegate {
        void didSelectAccount(int i);
    }

    public interface DatePickerDelegate {
        void didSelectDate(int i, int i2, int i3);
    }

    public interface PaymentAlertDelegate {
        void didPressedNewCard();
    }

    public interface ScheduleDatePickerDelegate {
        void didSelectDate(boolean z, int i);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:206:0x03b0  */
    /* JADX WARN: Removed duplicated region for block: B:240:0x044b  */
    /* JADX WARN: Removed duplicated region for block: B:310:0x0582  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.app.Dialog processError(int r16, im.uwrkaxlmjj.tgnet.TLRPC.TL_error r17, im.uwrkaxlmjj.ui.actionbar.BaseFragment r18, im.uwrkaxlmjj.tgnet.TLObject r19, java.lang.Object... r20) {
        /*
            Method dump skipped, instruction units count: 1672
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.AlertsCreator.processError(int, im.uwrkaxlmjj.tgnet.TLRPC$TL_error, im.uwrkaxlmjj.ui.actionbar.BaseFragment, im.uwrkaxlmjj.tgnet.TLObject, java.lang.Object[]):android.app.Dialog");
    }

    public static Toast showSimpleToast(BaseFragment baseFragment, String text) {
        ToastUtils.show((CharSequence) text);
        return ToastUtils.getToast();
    }

    public static AlertDialog showUpdateAppAlert(final Context context, String text, boolean updateApp) {
        if (context == null || text == null) {
            return null;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(text);
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        if (updateApp) {
            builder.setNegativeButton(LocaleController.getString("UpdateApp", R.string.UpdateApp), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$ir5CKwzfrZS9cXWrXLz5ZGMn-bI
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    Browser.openUrl(context, BuildVars.PLAYSTORE_APP_URL);
                }
            });
        }
        return builder.show();
    }

    public static AlertDialog.Builder createLanguageAlert(final LaunchActivity activity, final TLRPC.TL_langPackLanguage language) {
        String str;
        int end;
        if (language == null) {
            return null;
        }
        language.lang_code = language.lang_code.replace('-', '_').toLowerCase();
        language.plural_code = language.plural_code.replace('-', '_').toLowerCase();
        if (language.base_lang_code != null) {
            language.base_lang_code = language.base_lang_code.replace('-', '_').toLowerCase();
        }
        final AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        LocaleController.LocaleInfo currentInfo = LocaleController.getInstance().getCurrentLocaleInfo();
        if (currentInfo.shortName.equals(language.lang_code)) {
            builder.setTitle(LocaleController.getString("Language", R.string.Language));
            str = LocaleController.formatString("LanguageSame", R.string.LanguageSame, language.name);
            builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), null);
            builder.setNeutralButton(LocaleController.getString("SETTINGS", R.string.SETTINGS), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$E4dbN7cE6dzBw3DI3Gze6wQVDB8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    activity.lambda$runLinkRequest$26$LaunchActivity(new LanguageSelectActivity());
                }
            });
        } else if (language.strings_count == 0) {
            builder.setTitle(LocaleController.getString("LanguageUnknownTitle", R.string.LanguageUnknownTitle));
            str = LocaleController.formatString("LanguageUnknownCustomAlert", R.string.LanguageUnknownCustomAlert, language.name);
            builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), null);
        } else {
            builder.setTitle(LocaleController.getString("LanguageTitle", R.string.LanguageTitle));
            if (language.official) {
                str = LocaleController.formatString("LanguageAlert", R.string.LanguageAlert, language.name, Integer.valueOf((int) Math.ceil((language.translated_count / language.strings_count) * 100.0f)));
            } else {
                str = LocaleController.formatString("LanguageCustomAlert", R.string.LanguageCustomAlert, language.name, Integer.valueOf((int) Math.ceil((language.translated_count / language.strings_count) * 100.0f)));
            }
            builder.setPositiveButton(LocaleController.getString("Change", R.string.Change), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$bxjdPYqEen4udbWXU1jO99uouT0
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    AlertsCreator.lambda$createLanguageAlert$2(language, activity, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        }
        SpannableStringBuilder spanned = new SpannableStringBuilder(AndroidUtilities.replaceTags(str));
        int start = TextUtils.indexOf((CharSequence) spanned, '[');
        if (start != -1) {
            end = TextUtils.indexOf((CharSequence) spanned, ']', start + 1);
            if (start != -1 && end != -1) {
                spanned.delete(end, end + 1);
                spanned.delete(start, start + 1);
            }
        } else {
            end = -1;
        }
        if (start != -1 && end != -1) {
            spanned.setSpan(new URLSpanNoUnderline(language.translations_url) { // from class: im.uwrkaxlmjj.ui.components.AlertsCreator.1
                @Override // im.uwrkaxlmjj.ui.components.URLSpanNoUnderline, android.text.style.URLSpan, android.text.style.ClickableSpan
                public void onClick(View widget) {
                    builder.getDismissRunnable().run();
                    super.onClick(widget);
                }
            }, start, end - 1, 33);
        }
        TextView message = new TextView(activity);
        message.setText(spanned);
        message.setTextSize(1, 16.0f);
        message.setLinkTextColor(Theme.getColor(Theme.key_dialogTextLink));
        message.setHighlightColor(Theme.getColor(Theme.key_dialogLinkSelection));
        message.setPadding(AndroidUtilities.dp(23.0f), 0, AndroidUtilities.dp(23.0f), 0);
        message.setMovementMethod(new AndroidUtilities.LinkMovementMethodMy());
        message.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        builder.setView(message);
        return builder;
    }

    static /* synthetic */ void lambda$createLanguageAlert$2(TLRPC.TL_langPackLanguage language, LaunchActivity activity, DialogInterface dialogInterface, int i) {
        String key;
        if (language.official) {
            key = "remote_" + language.lang_code;
        } else {
            key = "unofficial_" + language.lang_code;
        }
        LocaleController.LocaleInfo localeInfo = LocaleController.getInstance().getLanguageFromDict(key);
        if (localeInfo == null) {
            localeInfo = new LocaleController.LocaleInfo();
            localeInfo.name = language.native_name;
            localeInfo.nameEnglish = language.name;
            localeInfo.shortName = language.lang_code;
            localeInfo.baseLangCode = language.base_lang_code;
            localeInfo.pluralLangCode = language.plural_code;
            localeInfo.isRtl = language.rtl;
            if (language.official) {
                localeInfo.pathToFile = "remote";
            } else {
                localeInfo.pathToFile = "unofficial";
            }
        }
        LocaleController.getInstance().applyLanguage(localeInfo, true, false, false, true, UserConfig.selectedAccount);
        activity.rebuildAllFragments(true);
    }

    public static boolean checkSlowMode(Context context, int currentAccount, long did, boolean few) {
        TLRPC.Chat chat;
        int lowerId = (int) did;
        if (lowerId < 0 && (chat = MessagesController.getInstance(currentAccount).getChat(Integer.valueOf(-lowerId))) != null && chat.slowmode_enabled && !ChatObject.hasAdminRights(chat)) {
            if (!few) {
                TLRPC.ChatFull chatFull = MessagesController.getInstance(currentAccount).getChatFull(chat.id);
                if (chatFull == null) {
                    chatFull = MessagesStorage.getInstance(currentAccount).loadChatInfo(chat.id, new CountDownLatch(1), false, false);
                }
                if (chatFull != null && chatFull.slowmode_next_send_date >= ConnectionsManager.getInstance(currentAccount).getCurrentTime()) {
                    few = true;
                }
            }
            if (few) {
                createSimpleAlert(context, chat.title, LocaleController.getString("SlowmodeSendError", R.string.SlowmodeSendError)).show();
                return true;
            }
        }
        return false;
    }

    public static AlertDialog.Builder createSimpleAlert(Context context, String text) {
        return createSimpleAlert(context, null, text);
    }

    public static AlertDialog.Builder createSimpleAlert(Context context, String title, String text) {
        if (text == null) {
            return null;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(title == null ? LocaleController.getString("AppName", R.string.AppName) : title);
        builder.setMessage(text);
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        return builder;
    }

    public static Dialog showSimpleAlert(BaseFragment baseFragment, String text) {
        return showSimpleAlert(baseFragment, null, text);
    }

    public static Dialog showSimpleAlert(BaseFragment baseFragment, String title, String text) {
        if (text == null || baseFragment == null || baseFragment.getParentActivity() == null) {
            return null;
        }
        AlertDialog.Builder builder = createSimpleAlert(baseFragment.getParentActivity(), title, text);
        Dialog dialog = builder.create();
        baseFragment.showDialog(dialog);
        return dialog;
    }

    public static void showBlockReportSpamAlert(BaseFragment fragment, final long dialog_id, final TLRPC.User currentUser, final TLRPC.Chat currentChat, final TLRPC.EncryptedChat encryptedChat, final boolean isLocation, TLRPC.ChatFull chatInfo, final MessagesStorage.IntCallback callback) {
        CharSequence reportText;
        CheckBoxCell[] cells;
        CharSequence reportText2;
        if (fragment == null || fragment.getParentActivity() == null) {
            return;
        }
        final AccountInstance accountInstance = fragment.getAccountInstance();
        AlertDialog.Builder builder = new AlertDialog.Builder(fragment.getParentActivity());
        SharedPreferences preferences = MessagesController.getNotificationsSettings(fragment.getCurrentAccount());
        boolean showReport = preferences.getBoolean("dialog_bar_report" + dialog_id, false);
        int i = 1;
        if (currentUser != null) {
            builder.setTitle(LocaleController.formatString("BlockUserTitle", R.string.BlockUserTitle, UserObject.getFirstName(currentUser)));
            builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("BlockUserAlert", R.string.BlockUserAlert, UserObject.getFirstName(currentUser))));
            CharSequence reportText3 = LocaleController.getString("BlockContact", R.string.BlockContact);
            final CheckBoxCell[] cells2 = new CheckBoxCell[2];
            LinearLayout linearLayout = new LinearLayout(fragment.getParentActivity());
            linearLayout.setOrientation(1);
            int a = 0;
            for (int i2 = 2; a < i2; i2 = 2) {
                if (a == 0 && !showReport) {
                    reportText2 = reportText3;
                } else {
                    cells2[a] = new CheckBoxCell(fragment.getParentActivity(), i);
                    cells2[a].setBackgroundDrawable(Theme.getSelectorDrawable(false));
                    cells2[a].setTag(Integer.valueOf(a));
                    if (a == 0) {
                        reportText2 = reportText3;
                        cells2[a].setText(LocaleController.getString("DeleteReportSpam", R.string.DeleteReportSpam), "", true, false);
                    } else {
                        reportText2 = reportText3;
                        if (a == 1) {
                            cells2[a].setText(LocaleController.formatString("DeleteThisChat", R.string.DeleteThisChat, new Object[0]), "", true, false);
                        }
                    }
                    cells2[a].setPadding(LocaleController.isRTL ? AndroidUtilities.dp(16.0f) : AndroidUtilities.dp(8.0f), 0, LocaleController.isRTL ? AndroidUtilities.dp(8.0f) : AndroidUtilities.dp(16.0f), 0);
                    linearLayout.addView(cells2[a], LayoutHelper.createLinear(-1, -2));
                    cells2[a].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$_9xATd7if7fiL6l5RIq10NAjj04
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            AlertsCreator.lambda$showBlockReportSpamAlert$3(cells2, view);
                        }
                    });
                }
                a++;
                reportText3 = reportText2;
                i = 1;
            }
            builder.setCustomViewOffset(12);
            builder.setView(linearLayout);
            cells = cells2;
            reportText = reportText3;
        } else {
            if (currentChat != null && isLocation) {
                builder.setTitle(LocaleController.getString("ReportUnrelatedGroup", R.string.ReportUnrelatedGroup));
                if (chatInfo != null && (chatInfo.location instanceof TLRPC.TL_channelLocation)) {
                    TLRPC.TL_channelLocation location = (TLRPC.TL_channelLocation) chatInfo.location;
                    builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("ReportUnrelatedGroupText", R.string.ReportUnrelatedGroupText, location.address)));
                } else {
                    builder.setMessage(LocaleController.getString("ReportUnrelatedGroupTextNoAddress", R.string.ReportUnrelatedGroupTextNoAddress));
                }
            } else {
                builder.setTitle(LocaleController.getString("ReportSpamTitle", R.string.ReportSpamTitle));
                if (ChatObject.isChannel(currentChat) && !currentChat.megagroup) {
                    builder.setMessage(LocaleController.getString("ReportSpamAlertChannel", R.string.ReportSpamAlertChannel));
                } else {
                    builder.setMessage(LocaleController.getString("ReportSpamAlertGroup", R.string.ReportSpamAlertGroup));
                }
            }
            reportText = LocaleController.getString("ReportChat", R.string.ReportChat);
            cells = null;
        }
        final CheckBoxCell[] checkBoxCellArr = cells;
        builder.setPositiveButton(reportText, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$JOC0H1nrSyJlr9G7sGi7oYOnTA4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i3) {
                AlertsCreator.lambda$showBlockReportSpamAlert$4(currentUser, accountInstance, checkBoxCellArr, dialog_id, currentChat, encryptedChat, isLocation, callback, dialogInterface, i3);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        AlertDialog dialog = builder.create();
        fragment.showDialog(dialog);
        TextView button = (TextView) dialog.getButton(-1);
        if (button != null) {
            button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
        }
    }

    static /* synthetic */ void lambda$showBlockReportSpamAlert$3(CheckBoxCell[] cells, View v) {
        Integer num = (Integer) v.getTag();
        cells[num.intValue()].setChecked(!cells[num.intValue()].isChecked(), true);
    }

    static /* synthetic */ void lambda$showBlockReportSpamAlert$4(TLRPC.User currentUser, AccountInstance accountInstance, CheckBoxCell[] cells, long dialog_id, TLRPC.Chat currentChat, TLRPC.EncryptedChat encryptedChat, boolean isLocation, MessagesStorage.IntCallback callback, DialogInterface dialogInterface, int i) {
        if (currentUser != null) {
            accountInstance.getMessagesController().blockUser(currentUser.id);
        }
        if (cells == null || (cells[0] != null && cells[0].isChecked())) {
            accountInstance.getMessagesController().reportSpam(dialog_id, currentUser, currentChat, encryptedChat, currentChat != null && isLocation);
        }
        if (cells == null || cells[1].isChecked()) {
            if (currentChat == null || ChatObject.isNotInChat(currentChat)) {
                accountInstance.getMessagesController().deleteDialog(dialog_id, 0);
            } else {
                accountInstance.getMessagesController().deleteUserFromChat((int) (-dialog_id), accountInstance.getMessagesController().getUser(Integer.valueOf(accountInstance.getUserConfig().getClientUserId())), null);
            }
            callback.run(1);
            return;
        }
        callback.run(0);
    }

    public static void showCustomNotificationsDialog(BaseFragment parentFragment, long did, int globalType, ArrayList<NotificationsSettingsActivity.NotificationException> exceptions, int currentAccount, MessagesStorage.IntCallback callback) {
        showCustomNotificationsDialog(parentFragment, did, globalType, exceptions, currentAccount, callback, null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v12, types: [android.view.View, android.widget.TextView] */
    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r10v3 */
    /* JADX WARN: Type inference failed for: r14v2, types: [android.view.View] */
    /* JADX WARN: Type inference failed for: r14v3 */
    /* JADX WARN: Type inference failed for: r14v4 */
    /* JADX WARN: Type inference failed for: r14v6 */
    /* JADX WARN: Type inference failed for: r15v0 */
    /* JADX WARN: Type inference failed for: r15v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r15v3 */
    /* JADX WARN: Type inference failed for: r18v0, types: [im.uwrkaxlmjj.ui.actionbar.AlertDialog$Builder] */
    /* JADX WARN: Type inference failed for: r7v1, types: [android.widget.LinearLayout] */
    /* JADX WARN: Type inference failed for: r7v3 */
    /* JADX WARN: Type inference failed for: r7v4 */
    public static void showCustomNotificationsDialog(final BaseFragment baseFragment, final long j, final int i, final ArrayList<NotificationsSettingsActivity.NotificationException> arrayList, final int i2, final MessagesStorage.IntCallback intCallback, final MessagesStorage.IntCallback intCallback2) {
        int i3;
        final AlertDialog.Builder builder;
        boolean z;
        ?? r14;
        String[] strArr;
        Drawable drawable;
        if (baseFragment == null || baseFragment.getParentActivity() == null) {
            return;
        }
        boolean zIsGlobalNotificationsEnabled = NotificationsController.getInstance(i2).isGlobalNotificationsEnabled(j);
        String[] strArr2 = new String[5];
        ?? r15 = 0;
        strArr2[0] = LocaleController.getString("NotificationsTurnOn", R.string.NotificationsTurnOn);
        ?? r10 = 1;
        strArr2[1] = LocaleController.formatString("MuteFor", R.string.MuteFor, LocaleController.formatPluralString("Hours", 1));
        strArr2[2] = LocaleController.formatString("MuteFor", R.string.MuteFor, LocaleController.formatPluralString("Days", 2));
        Drawable drawable2 = null;
        strArr2[3] = (j == 0 && (baseFragment instanceof NotificationsCustomSettingsActivity)) ? null : LocaleController.getString("NotificationsCustomize", R.string.NotificationsCustomize);
        strArr2[4] = LocaleController.getString("NotificationsTurnOff", R.string.NotificationsTurnOff);
        String[] strArr3 = strArr2;
        int[] iArr = {R.drawable.notifications_on, R.drawable.notifications_mute1h, R.drawable.notifications_mute2d, R.drawable.notifications_settings, R.drawable.notifications_off};
        LinearLayout linearLayout = new LinearLayout(baseFragment.getParentActivity());
        linearLayout.setOrientation(1);
        AlertDialog.Builder builder2 = new AlertDialog.Builder(baseFragment.getParentActivity());
        int i4 = 0;
        ?? r7 = linearLayout;
        while (i4 < strArr3.length) {
            if (strArr3[i4] == null) {
                i3 = i4;
                builder = builder2;
                strArr = strArr3;
                drawable = drawable2;
                z = zIsGlobalNotificationsEnabled;
                r14 = r7;
            } else {
                ?? textView = new TextView(baseFragment.getParentActivity());
                Drawable drawable3 = baseFragment.getParentActivity().getResources().getDrawable(iArr[i4]);
                if (i4 == strArr3.length - r10) {
                    textView.setTextColor(Theme.getColor(Theme.key_dialogTextRed));
                    drawable3.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogRedIcon), PorterDuff.Mode.MULTIPLY));
                } else {
                    textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                    drawable3.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogIcon), PorterDuff.Mode.MULTIPLY));
                }
                textView.setTextSize(r10, 16.0f);
                textView.setLines(r10);
                textView.setMaxLines(r10);
                textView.setCompoundDrawablesWithIntrinsicBounds(drawable3, drawable2, drawable2, drawable2);
                textView.setTag(Integer.valueOf(i4));
                textView.setBackgroundDrawable(Theme.getSelectorDrawable(r15));
                textView.setPadding(AndroidUtilities.dp(24.0f), r15, AndroidUtilities.dp(24.0f), r15);
                textView.setSingleLine(r10);
                textView.setGravity(19);
                textView.setCompoundDrawablePadding(AndroidUtilities.dp(26.0f));
                textView.setText(strArr3[i4]);
                r7.addView(textView, LayoutHelper.createLinear(-1, 48, 51));
                final boolean z2 = zIsGlobalNotificationsEnabled;
                i3 = i4;
                builder = builder2;
                z = zIsGlobalNotificationsEnabled;
                r14 = r7;
                strArr = strArr3;
                drawable = drawable2;
                textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$Xb7IgSbiP30vFpgPftfBF5jdR14
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        AlertsCreator.lambda$showCustomNotificationsDialog$5(j, i2, z2, intCallback2, i, baseFragment, arrayList, intCallback, builder, view);
                    }
                });
            }
            i4 = i3 + 1;
            r7 = r14;
            builder2 = builder;
            zIsGlobalNotificationsEnabled = z;
            strArr3 = strArr;
            drawable2 = drawable;
            r10 = 1;
            r15 = 0;
        }
        ?? r18 = builder2;
        r18.setTitle(LocaleController.getString("Notifications", R.string.Notifications));
        r18.setView(r7);
        baseFragment.showDialog(r18.create());
    }

    static /* synthetic */ void lambda$showCustomNotificationsDialog$5(long did, int currentAccount, boolean defaultEnabled, MessagesStorage.IntCallback resultCallback, int globalType, BaseFragment parentFragment, ArrayList exceptions, MessagesStorage.IntCallback callback, AlertDialog.Builder builder, View v) {
        long flags;
        int i = ((Integer) v.getTag()).intValue();
        if (i == 0) {
            if (did != 0) {
                SharedPreferences preferences = MessagesController.getNotificationsSettings(currentAccount);
                SharedPreferences.Editor editor = preferences.edit();
                if (defaultEnabled) {
                    editor.remove("notify2_" + did);
                } else {
                    editor.putInt("notify2_" + did, 0);
                }
                MessagesStorage.getInstance(currentAccount).setDialogFlags(did, 0L);
                editor.commit();
                TLRPC.Dialog dialog = MessagesController.getInstance(currentAccount).dialogs_dict.get(did);
                if (dialog != null) {
                    dialog.notify_settings = new TLRPC.TL_peerNotifySettings();
                }
                NotificationsController.getInstance(currentAccount).updateServerNotificationsSettings(did);
                if (resultCallback != null) {
                    if (defaultEnabled) {
                        resultCallback.run(0);
                    } else {
                        resultCallback.run(1);
                    }
                }
            } else {
                NotificationsController.getInstance(currentAccount).setGlobalNotificationsEnabled(globalType, 0);
            }
        } else if (i != 3) {
            int untilTime = ConnectionsManager.getInstance(currentAccount).getCurrentTime();
            if (i == 1) {
                untilTime += 3600;
            } else if (i == 2) {
                untilTime += 172800;
            } else if (i == 4) {
                untilTime = Integer.MAX_VALUE;
            }
            if (did != 0) {
                SharedPreferences preferences2 = MessagesController.getNotificationsSettings(currentAccount);
                SharedPreferences.Editor editor2 = preferences2.edit();
                if (i == 4) {
                    if (!defaultEnabled) {
                        editor2.remove("notify2_" + did);
                        flags = 0;
                    } else {
                        editor2.putInt("notify2_" + did, 2);
                        flags = 1;
                    }
                } else {
                    editor2.putInt("notify2_" + did, 3);
                    editor2.putInt("notifyuntil_" + did, untilTime);
                    flags = (((long) untilTime) << 32) | 1;
                }
                NotificationsController.getInstance(currentAccount).removeNotificationsForDialog(did);
                MessagesStorage.getInstance(currentAccount).setDialogFlags(did, flags);
                editor2.commit();
                TLRPC.Dialog dialog2 = MessagesController.getInstance(currentAccount).dialogs_dict.get(did);
                if (dialog2 != null) {
                    dialog2.notify_settings = new TLRPC.TL_peerNotifySettings();
                    if (i != 4 || defaultEnabled) {
                        dialog2.notify_settings.mute_until = untilTime;
                    }
                }
                NotificationsController.getInstance(currentAccount).updateServerNotificationsSettings(did);
                if (resultCallback != null) {
                    if (i == 4 && !defaultEnabled) {
                        resultCallback.run(0);
                    } else {
                        resultCallback.run(1);
                    }
                }
            } else if (i == 4) {
                NotificationsController.getInstance(currentAccount).setGlobalNotificationsEnabled(globalType, Integer.MAX_VALUE);
            } else {
                NotificationsController.getInstance(currentAccount).setGlobalNotificationsEnabled(globalType, untilTime);
            }
        } else if (did != 0) {
            Bundle args = new Bundle();
            args.putLong("dialog_id", did);
            parentFragment.presentFragment(new ProfileNotificationsActivity(args));
        } else {
            parentFragment.presentFragment(new NotificationsCustomSettingsActivity(globalType, exceptions));
        }
        if (callback != null) {
            callback.run(i);
        }
        builder.getDismissRunnable().run();
    }

    public static AlertDialog showSecretLocationAlert(Context context, int currentAccount, final Runnable onSelectRunnable, boolean inChat) {
        ArrayList<String> arrayList = new ArrayList<>();
        int providers = MessagesController.getInstance(currentAccount).availableMapProviders;
        if ((providers & 1) != 0) {
            arrayList.add(LocaleController.getString("MapPreviewProviderApp", R.string.MapPreviewProviderApp));
        }
        if ((providers & 2) != 0) {
            arrayList.add(LocaleController.getString("MapPreviewProviderGoogle", R.string.MapPreviewProviderGoogle));
        }
        if ((providers & 4) != 0) {
            arrayList.add(LocaleController.getString("MapPreviewProviderYandex", R.string.MapPreviewProviderYandex));
        }
        arrayList.add(LocaleController.getString("MapPreviewProviderNobody", R.string.MapPreviewProviderNobody));
        AlertDialog.Builder builder = new AlertDialog.Builder(context).setTitle(LocaleController.getString("ChooseMapPreviewProvider", R.string.ChooseMapPreviewProvider)).setItems((CharSequence[]) arrayList.toArray(new String[0]), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$pByjLUgiwxze1_8embGs9cyDGa8
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                AlertsCreator.lambda$showSecretLocationAlert$6(onSelectRunnable, dialogInterface, i);
            }
        });
        if (!inChat) {
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        }
        AlertDialog dialog = builder.show();
        if (inChat) {
            dialog.setCanceledOnTouchOutside(false);
        }
        return dialog;
    }

    static /* synthetic */ void lambda$showSecretLocationAlert$6(Runnable onSelectRunnable, DialogInterface dialog, int which) {
        SharedConfig.setSecretMapPreviewType(which);
        if (onSelectRunnable != null) {
            onSelectRunnable.run();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void updateDayPicker(NumberPicker dayPicker, NumberPicker monthPicker, NumberPicker yearPicker) {
        Calendar calendar = Calendar.getInstance();
        calendar.set(2, monthPicker.getValue());
        calendar.set(1, yearPicker.getValue());
        dayPicker.setMinValue(1);
        dayPicker.setMaxValue(calendar.getActualMaximum(5));
    }

    private static void checkPickerDate(NumberPicker dayPicker, NumberPicker monthPicker, NumberPicker yearPicker) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(System.currentTimeMillis());
        int currentYear = calendar.get(1);
        int currentMonth = calendar.get(2);
        int currentDay = calendar.get(5);
        if (currentYear > yearPicker.getValue()) {
            yearPicker.setValue(currentYear);
        }
        if (yearPicker.getValue() == currentYear) {
            if (currentMonth > monthPicker.getValue()) {
                monthPicker.setValue(currentMonth);
            }
            if (currentMonth == monthPicker.getValue() && currentDay > dayPicker.getValue()) {
                dayPicker.setValue(currentDay);
            }
        }
    }

    public static AlertDialog createSupportAlert(final BaseFragment fragment) {
        if (fragment == null || fragment.getParentActivity() == null) {
            return null;
        }
        TextView textView = new TextView(fragment.getParentActivity());
        Spannable spanned = new SpannableString(Html.fromHtml(LocaleController.getString("AskAQuestionInfo", R.string.AskAQuestionInfo).replace(ShellAdbUtils.COMMAND_LINE_END, "<br>")));
        URLSpan[] spans = (URLSpan[]) spanned.getSpans(0, spanned.length(), URLSpan.class);
        for (URLSpan span : spans) {
            int start = spanned.getSpanStart(span);
            int end = spanned.getSpanEnd(span);
            spanned.removeSpan(span);
            spanned.setSpan(new URLSpanNoUnderline(span.getURL()) { // from class: im.uwrkaxlmjj.ui.components.AlertsCreator.2
                @Override // im.uwrkaxlmjj.ui.components.URLSpanNoUnderline, android.text.style.URLSpan, android.text.style.ClickableSpan
                public void onClick(View widget) {
                    fragment.dismissCurrentDialog();
                    super.onClick(widget);
                }
            }, start, end, 0);
        }
        textView.setText(spanned);
        textView.setTextSize(1, 16.0f);
        textView.setLinkTextColor(Theme.getColor(Theme.key_dialogTextLink));
        textView.setHighlightColor(Theme.getColor(Theme.key_dialogLinkSelection));
        textView.setPadding(AndroidUtilities.dp(23.0f), 0, AndroidUtilities.dp(23.0f), 0);
        textView.setMovementMethod(new AndroidUtilities.LinkMovementMethodMy());
        textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        AlertDialog.Builder builder = new AlertDialog.Builder(fragment.getParentActivity());
        builder.setView(textView);
        builder.setTitle(LocaleController.getString("AskAQuestion", R.string.AskAQuestion));
        builder.setPositiveButton(LocaleController.getString("AskButton", R.string.AskButton), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$Qzmgw4qNLCE-6ASnFRpg9t_7Q9M
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                AlertsCreator.performAskAQuestion(fragment);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        return builder.create();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void performAskAQuestion(final BaseFragment fragment) {
        String userString;
        final int currentAccount = fragment.getCurrentAccount();
        final SharedPreferences preferences = MessagesController.getMainSettings(currentAccount);
        int uid = preferences.getInt("support_id", 0);
        TLRPC.User supportUser = null;
        if (uid != 0 && (supportUser = MessagesController.getInstance(currentAccount).getUser(Integer.valueOf(uid))) == null && (userString = preferences.getString("support_user", null)) != null) {
            try {
                byte[] datacentersBytes = Base64.decode(userString, 0);
                if (datacentersBytes != null) {
                    SerializedData data = new SerializedData(datacentersBytes);
                    supportUser = TLRPC.User.TLdeserialize(data, data.readInt32(false), false);
                    if (supportUser != null && supportUser.id == 333000) {
                        supportUser = null;
                    }
                    data.cleanup();
                }
            } catch (Exception e) {
                FileLog.e(e);
                supportUser = null;
            }
        }
        if (supportUser == null) {
            final AlertDialog progressDialog = new AlertDialog(fragment.getParentActivity(), 3);
            progressDialog.setCanCancel(false);
            progressDialog.show();
            TLRPC.TL_help_getSupport req = new TLRPC.TL_help_getSupport();
            ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$pyL8nqkKbYOBf9_AFbuhJiKyUYE
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    AlertsCreator.lambda$performAskAQuestion$10(preferences, progressDialog, currentAccount, fragment, tLObject, tL_error);
                }
            });
            return;
        }
        MessagesController.getInstance(currentAccount).putUser(supportUser, true);
        Bundle args = new Bundle();
        args.putInt("user_id", supportUser.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$performAskAQuestion$10(final SharedPreferences preferences, final AlertDialog progressDialog, final int currentAccount, final BaseFragment fragment, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.TL_help_support res = (TLRPC.TL_help_support) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$4EskIZSydQ8XaSzmsWGdGmoIJtQ
                @Override // java.lang.Runnable
                public final void run() {
                    AlertsCreator.lambda$null$8(preferences, res, progressDialog, currentAccount, fragment);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$s-SsEokqSAsjYuZ3779Yq5v29tA
                @Override // java.lang.Runnable
                public final void run() {
                    AlertsCreator.lambda$null$9(progressDialog);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$8(SharedPreferences preferences, TLRPC.TL_help_support res, AlertDialog progressDialog, int currentAccount, BaseFragment fragment) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt("support_id", res.user.id);
        SerializedData data = new SerializedData();
        res.user.serializeToStream(data);
        editor.putString("support_user", Base64.encodeToString(data.toByteArray(), 0));
        editor.commit();
        data.cleanup();
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        ArrayList<TLRPC.User> users = new ArrayList<>();
        users.add(res.user);
        MessagesStorage.getInstance(currentAccount).putUsersAndChats(users, null, true, true);
        MessagesController.getInstance(currentAccount).putUser(res.user, false);
        Bundle args = new Bundle();
        args.putInt("user_id", res.user.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$null$9(AlertDialog progressDialog) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void createClearOrDeleteDialogAlert(BaseFragment fragment, boolean clear, TLRPC.Chat chat, TLRPC.User user, boolean secret, MessagesStorage.BooleanCallback onProcessRunnable) {
        createClearOrDeleteDialogAlert(fragment, clear, false, false, chat, user, secret, onProcessRunnable);
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x028d  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x029c  */
    /* JADX WARN: Removed duplicated region for block: B:107:0x02ae  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x042d  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x0439  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x04f5  */
    /* JADX WARN: Removed duplicated region for block: B:177:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0266  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0275  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void createClearOrDeleteDialogAlert(final im.uwrkaxlmjj.ui.actionbar.BaseFragment r41, final boolean r42, final boolean r43, final boolean r44, final im.uwrkaxlmjj.tgnet.TLRPC.Chat r45, final im.uwrkaxlmjj.tgnet.TLRPC.User r46, final boolean r47, final im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback r48) {
        /*
            Method dump skipped, instruction units count: 1281
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.AlertsCreator.createClearOrDeleteDialogAlert(im.uwrkaxlmjj.ui.actionbar.BaseFragment, boolean, boolean, boolean, im.uwrkaxlmjj.tgnet.TLRPC$Chat, im.uwrkaxlmjj.tgnet.TLRPC$User, boolean, im.uwrkaxlmjj.messenger.MessagesStorage$BooleanCallback):void");
    }

    static /* synthetic */ void lambda$createClearOrDeleteDialogAlert$11(boolean[] deleteForAll, View v) {
        CheckBoxCell cell1 = (CheckBoxCell) v;
        deleteForAll[0] = !deleteForAll[0];
        cell1.setChecked(deleteForAll[0], true);
    }

    static /* synthetic */ void lambda$createClearOrDeleteDialogAlert$13(final TLRPC.User user, boolean clearingCache, boolean second, final boolean[] deleteForAll, final BaseFragment fragment, final boolean clear, final boolean admin, final TLRPC.Chat chat, final boolean secret, final MessagesStorage.BooleanCallback onProcessRunnable, DialogInterface dialogInterface, int i) {
        if (user != null && !clearingCache && !second && deleteForAll[0]) {
            MessagesStorage.getInstance(fragment.getCurrentAccount()).getMessagesCount(user.id, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$xh-aMDTH9XPYmHC_kL1yd9FAjaQ
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                public final void run(int i2) {
                    AlertsCreator.lambda$null$12(fragment, clear, admin, chat, user, secret, onProcessRunnable, deleteForAll, i2);
                }
            });
        } else if (onProcessRunnable != null) {
            onProcessRunnable.run(second || deleteForAll[0]);
        }
    }

    static /* synthetic */ void lambda$null$12(BaseFragment fragment, boolean clear, boolean admin, TLRPC.Chat chat, TLRPC.User user, boolean secret, MessagesStorage.BooleanCallback onProcessRunnable, boolean[] deleteForAll, int count) {
        if (count >= 50) {
            createClearOrDeleteDialogAlert(fragment, clear, admin, true, chat, user, secret, onProcessRunnable);
        } else if (onProcessRunnable != null) {
            onProcessRunnable.run(deleteForAll[0]);
        }
    }

    public static AlertDialog.Builder createDatePickerDialog(Context context, int minYear, int maxYear, int currentYearDiff, int selectedDay, int selectedMonth, int selectedYear, String title, final boolean checkMinDate, final DatePickerDelegate datePickerDelegate) {
        if (context == null) {
            return null;
        }
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(0);
        linearLayout.setWeightSum(1.0f);
        final NumberPicker monthPicker = new NumberPicker(context);
        final NumberPicker dayPicker = new NumberPicker(context);
        final NumberPicker yearPicker = new NumberPicker(context);
        linearLayout.addView(dayPicker, LayoutHelper.createLinear(0, -2, 0.3f));
        dayPicker.setOnScrollListener(new NumberPicker.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$qmwVBhsAlo-ZtKY63JRDnCYVDXU
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.OnScrollListener
            public final void onScrollStateChange(NumberPicker numberPicker, int i) {
                AlertsCreator.lambda$createDatePickerDialog$14(checkMinDate, dayPicker, monthPicker, yearPicker, numberPicker, i);
            }
        });
        monthPicker.setMinValue(0);
        monthPicker.setMaxValue(11);
        linearLayout.addView(monthPicker, LayoutHelper.createLinear(0, -2, 0.3f));
        monthPicker.setFormatter(new NumberPicker.Formatter() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$VEBYiUNWpiE9cNRepcj0cpDYyJc
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.Formatter
            public final String format(int i) {
                return AlertsCreator.lambda$createDatePickerDialog$15(i);
            }
        });
        monthPicker.setOnValueChangedListener(new NumberPicker.OnValueChangeListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$JnmRwOKWH5Z-IEbuldL7-BlWBRE
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.OnValueChangeListener
            public final void onValueChange(NumberPicker numberPicker, int i, int i2) {
                AlertsCreator.updateDayPicker(dayPicker, monthPicker, yearPicker);
            }
        });
        monthPicker.setOnScrollListener(new NumberPicker.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$zV-_N4Rjy4INVuWC0w6RZChdyO4
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.OnScrollListener
            public final void onScrollStateChange(NumberPicker numberPicker, int i) {
                AlertsCreator.lambda$createDatePickerDialog$17(checkMinDate, dayPicker, monthPicker, yearPicker, numberPicker, i);
            }
        });
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(System.currentTimeMillis());
        int currentYear = calendar.get(1);
        yearPicker.setMinValue(currentYear + minYear);
        yearPicker.setMaxValue(currentYear + maxYear);
        yearPicker.setValue(currentYear + currentYearDiff);
        linearLayout.addView(yearPicker, LayoutHelper.createLinear(0, -2, 0.4f));
        yearPicker.setOnValueChangedListener(new NumberPicker.OnValueChangeListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$3EFzCnCrpKFPvoY1B4Fio0iaikk
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.OnValueChangeListener
            public final void onValueChange(NumberPicker numberPicker, int i, int i2) {
                AlertsCreator.updateDayPicker(dayPicker, monthPicker, yearPicker);
            }
        });
        yearPicker.setOnScrollListener(new NumberPicker.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$kdUFDdwjt0c96uqsBXKTXmSfDeY
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.OnScrollListener
            public final void onScrollStateChange(NumberPicker numberPicker, int i) {
                AlertsCreator.lambda$createDatePickerDialog$19(checkMinDate, dayPicker, monthPicker, yearPicker, numberPicker, i);
            }
        });
        updateDayPicker(dayPicker, monthPicker, yearPicker);
        if (checkMinDate) {
            checkPickerDate(dayPicker, monthPicker, yearPicker);
        }
        if (selectedDay != -1) {
            dayPicker.setValue(selectedDay);
            monthPicker.setValue(selectedMonth);
            yearPicker.setValue(selectedYear);
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(title);
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("Set", R.string.Set), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$MI0X4_rJ_kbdnt8IUvLV90VzABM
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                AlertsCreator.lambda$createDatePickerDialog$20(checkMinDate, dayPicker, monthPicker, yearPicker, datePickerDelegate, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        return builder;
    }

    static /* synthetic */ void lambda$createDatePickerDialog$14(boolean checkMinDate, NumberPicker dayPicker, NumberPicker monthPicker, NumberPicker yearPicker, NumberPicker view, int scrollState) {
        if (checkMinDate && scrollState == 0) {
            checkPickerDate(dayPicker, monthPicker, yearPicker);
        }
    }

    static /* synthetic */ String lambda$createDatePickerDialog$15(int value) {
        Calendar calendar = Calendar.getInstance();
        calendar.set(5, 1);
        calendar.set(2, value);
        return calendar.getDisplayName(2, 1, Locale.getDefault());
    }

    static /* synthetic */ void lambda$createDatePickerDialog$17(boolean checkMinDate, NumberPicker dayPicker, NumberPicker monthPicker, NumberPicker yearPicker, NumberPicker view, int scrollState) {
        if (checkMinDate && scrollState == 0) {
            checkPickerDate(dayPicker, monthPicker, yearPicker);
        }
    }

    static /* synthetic */ void lambda$createDatePickerDialog$19(boolean checkMinDate, NumberPicker dayPicker, NumberPicker monthPicker, NumberPicker yearPicker, NumberPicker view, int scrollState) {
        if (checkMinDate && scrollState == 0) {
            checkPickerDate(dayPicker, monthPicker, yearPicker);
        }
    }

    static /* synthetic */ void lambda$createDatePickerDialog$20(boolean checkMinDate, NumberPicker dayPicker, NumberPicker monthPicker, NumberPicker yearPicker, DatePickerDelegate datePickerDelegate, DialogInterface dialog, int which) {
        if (checkMinDate) {
            checkPickerDate(dayPicker, monthPicker, yearPicker);
        }
        datePickerDelegate.didSelectDate(yearPicker.getValue(), monthPicker.getValue(), dayPicker.getValue());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean checkScheduleDate(TextView button, boolean reminder, NumberPicker dayPicker, NumberPicker hourPicker, NumberPicker minutePicker) {
        long currentTime;
        int num;
        int day = dayPicker.getValue();
        int hour = hourPicker.getValue();
        int minute = minutePicker.getValue();
        Calendar calendar = Calendar.getInstance();
        long systemTime = System.currentTimeMillis();
        calendar.setTimeInMillis(systemTime);
        int currentYear = calendar.get(1);
        int currentDay = calendar.get(6);
        calendar.setTimeInMillis(System.currentTimeMillis() + (((long) day) * 24 * 3600 * 1000));
        calendar.set(11, hour);
        calendar.set(12, minute);
        long currentTime2 = calendar.getTimeInMillis();
        if (currentTime2 <= systemTime + DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS) {
            currentTime = currentTime2;
            calendar.setTimeInMillis(systemTime + DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS);
            if (currentDay != calendar.get(6)) {
                day = 1;
                dayPicker.setValue(1);
            }
            int i = calendar.get(11);
            hour = i;
            hourPicker.setValue(i);
            int i2 = calendar.get(12);
            minute = i2;
            minutePicker.setValue(i2);
        } else {
            currentTime = currentTime2;
        }
        int selectedYear = calendar.get(1);
        calendar.setTimeInMillis(System.currentTimeMillis() + (((long) day) * 24 * 3600 * 1000));
        calendar.set(11, hour);
        calendar.set(12, minute);
        if (button != null) {
            long time = calendar.getTimeInMillis();
            if (day == 0) {
                num = 0;
            } else if (currentYear == selectedYear) {
                num = 1;
            } else {
                num = 2;
            }
            if (reminder) {
                num += 3;
            }
            button.setText(LocaleController.getInstance().formatterScheduleSend[num].format(time));
        }
        return currentTime - systemTime > DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS;
    }

    public static BottomSheet.Builder createScheduleDatePickerDialog(Context context, boolean reminder, ScheduleDatePickerDelegate datePickerDelegate) {
        return createScheduleDatePickerDialog(context, reminder, -1L, datePickerDelegate, null);
    }

    public static BottomSheet.Builder createScheduleDatePickerDialog(Context context, boolean reminder, ScheduleDatePickerDelegate datePickerDelegate, Runnable cancelRunnable) {
        return createScheduleDatePickerDialog(context, reminder, -1L, datePickerDelegate, cancelRunnable);
    }

    public static BottomSheet.Builder createScheduleDatePickerDialog(Context context, final boolean reminder, long currentDate, final ScheduleDatePickerDelegate datePickerDelegate, final Runnable cancelRunnable) {
        int i;
        String str;
        TextView buttonTextView;
        Calendar calendar;
        if (context != null) {
            final BottomSheet.Builder builder = new BottomSheet.Builder(context, false, 1);
            builder.setApplyBottomPadding(false);
            final NumberPicker dayPicker = new NumberPicker(context);
            dayPicker.setTextOffset(AndroidUtilities.dp(10.0f));
            dayPicker.setItemCount(5);
            final NumberPicker hourPicker = new NumberPicker(context);
            hourPicker.setItemCount(5);
            hourPicker.setTextOffset(-AndroidUtilities.dp(10.0f));
            final NumberPicker minutePicker = new NumberPicker(context);
            minutePicker.setItemCount(5);
            minutePicker.setTextOffset(-AndroidUtilities.dp(34.0f));
            LinearLayout container = new LinearLayout(context) { // from class: im.uwrkaxlmjj.ui.components.AlertsCreator.4
                boolean ignoreLayout = false;

                @Override // android.widget.LinearLayout, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    int count;
                    this.ignoreLayout = true;
                    if (AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y) {
                        count = 3;
                    } else {
                        count = 5;
                    }
                    dayPicker.setItemCount(count);
                    hourPicker.setItemCount(count);
                    minutePicker.setItemCount(count);
                    dayPicker.getLayoutParams().height = AndroidUtilities.dp(54.0f) * count;
                    hourPicker.getLayoutParams().height = AndroidUtilities.dp(54.0f) * count;
                    minutePicker.getLayoutParams().height = AndroidUtilities.dp(54.0f) * count;
                    this.ignoreLayout = false;
                    super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                }

                @Override // android.view.View, android.view.ViewParent
                public void requestLayout() {
                    if (this.ignoreLayout) {
                        return;
                    }
                    super.requestLayout();
                }
            };
            container.setOrientation(1);
            TextView titleView = new TextView(context);
            if (reminder) {
                i = R.string.SetReminder;
                str = "SetReminder";
            } else {
                i = R.string.ScheduleMessage;
                str = "ScheduleMessage";
            }
            titleView.setText(LocaleController.getString(str, i));
            titleView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            titleView.setTextSize(1, 20.0f);
            titleView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            container.addView(titleView, LayoutHelper.createLinear(-1, -2, 51, 22, 12, 22, 4));
            titleView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$GnEZ_JARM3kmF3yBrscb1sYzeGU
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view, MotionEvent motionEvent) {
                    return AlertsCreator.lambda$createScheduleDatePickerDialog$21(view, motionEvent);
                }
            });
            LinearLayout linearLayout = new LinearLayout(context);
            linearLayout.setOrientation(0);
            linearLayout.setWeightSum(1.0f);
            container.addView(linearLayout, LayoutHelper.createLinear(-1, -2));
            final long currentTime = System.currentTimeMillis();
            final Calendar calendar2 = Calendar.getInstance();
            calendar2.setTimeInMillis(currentTime);
            final int currentYear = calendar2.get(1);
            final TextView buttonTextView2 = new TextView(context);
            linearLayout.addView(dayPicker, LayoutHelper.createLinear(0, JavaScreenCapturer.DEGREE_270, 0.5f));
            dayPicker.setMinValue(0);
            dayPicker.setMaxValue(365);
            dayPicker.setWrapSelectorWheel(false);
            dayPicker.setFormatter(new NumberPicker.Formatter() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$b1yFk-Azi7N8MX-LLgrHElywQ3M
                @Override // im.uwrkaxlmjj.ui.components.NumberPicker.Formatter
                public final String format(int i2) {
                    return AlertsCreator.lambda$createScheduleDatePickerDialog$22(currentTime, calendar2, currentYear, i2);
                }
            });
            NumberPicker.OnValueChangeListener onValueChangeListener = new NumberPicker.OnValueChangeListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$Ko3USeHzFUheFYHMb6odPv-Qgu0
                @Override // im.uwrkaxlmjj.ui.components.NumberPicker.OnValueChangeListener
                public final void onValueChange(NumberPicker numberPicker, int i2, int i3) {
                    AlertsCreator.checkScheduleDate(buttonTextView2, reminder, dayPicker, hourPicker, minutePicker);
                }
            };
            dayPicker.setOnValueChangedListener(onValueChangeListener);
            hourPicker.setMinValue(0);
            hourPicker.setMaxValue(23);
            linearLayout.addView(hourPicker, LayoutHelper.createLinear(0, JavaScreenCapturer.DEGREE_270, 0.2f));
            hourPicker.setFormatter(new NumberPicker.Formatter() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$zk9wNI0mKLWhbn_KDUoaAYV0PBU
                @Override // im.uwrkaxlmjj.ui.components.NumberPicker.Formatter
                public final String format(int i2) {
                    return String.format("%02d", Integer.valueOf(i2));
                }
            });
            hourPicker.setOnValueChangedListener(onValueChangeListener);
            minutePicker.setMinValue(0);
            minutePicker.setMaxValue(59);
            minutePicker.setValue(0);
            minutePicker.setFormatter(new NumberPicker.Formatter() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$ta7x9Tp37GrGZSBHHoOBq5J7AAk
                @Override // im.uwrkaxlmjj.ui.components.NumberPicker.Formatter
                public final String format(int i2) {
                    return String.format("%02d", Integer.valueOf(i2));
                }
            });
            linearLayout.addView(minutePicker, LayoutHelper.createLinear(0, JavaScreenCapturer.DEGREE_270, 0.3f));
            minutePicker.setOnValueChangedListener(onValueChangeListener);
            if (currentDate <= 0) {
                buttonTextView = buttonTextView2;
                calendar = calendar2;
            } else {
                long currentDate2 = 1000 * currentDate;
                calendar = calendar2;
                calendar.setTimeInMillis(System.currentTimeMillis());
                calendar.set(12, 0);
                calendar.set(11, 0);
                buttonTextView = buttonTextView2;
                int days = (int) ((currentDate2 - calendar.getTimeInMillis()) / 86400000);
                calendar.setTimeInMillis(currentDate2);
                if (days >= 0) {
                    minutePicker.setValue(calendar.get(12));
                    hourPicker.setValue(calendar.get(11));
                    dayPicker.setValue(days);
                }
            }
            final boolean[] canceled = {true};
            TextView buttonTextView3 = buttonTextView;
            checkScheduleDate(buttonTextView3, reminder, dayPicker, hourPicker, minutePicker);
            buttonTextView3.setPadding(AndroidUtilities.dp(34.0f), 0, AndroidUtilities.dp(34.0f), 0);
            buttonTextView3.setGravity(17);
            buttonTextView3.setTextColor(Theme.getColor(Theme.key_featuredStickers_buttonText));
            buttonTextView3.setTextSize(1, 14.0f);
            buttonTextView3.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            buttonTextView3.setBackgroundDrawable(Theme.createSimpleSelectorRoundRectDrawable(AndroidUtilities.dp(4.0f), Theme.getColor(Theme.key_featuredStickers_addButton), Theme.getColor(Theme.key_featuredStickers_addButtonPressed)));
            container.addView(buttonTextView3, LayoutHelper.createLinear(-1, 48, 83, 16, 15, 16, 16));
            final Calendar calendar3 = calendar;
            buttonTextView3.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$qUUnJYLwXpQJee2ArM3HYqhmaDc
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    AlertsCreator.lambda$createScheduleDatePickerDialog$26(canceled, reminder, dayPicker, hourPicker, minutePicker, calendar3, datePickerDelegate, builder, view);
                }
            });
            builder.setCustomView(container);
            builder.show().setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$j2UrVhS-Uc4mk4geoLpQ9WxuE_Y
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    AlertsCreator.lambda$createScheduleDatePickerDialog$27(cancelRunnable, canceled, dialogInterface);
                }
            });
            return builder;
        }
        return null;
    }

    static /* synthetic */ boolean lambda$createScheduleDatePickerDialog$21(View v, MotionEvent event) {
        return true;
    }

    static /* synthetic */ String lambda$createScheduleDatePickerDialog$22(long currentTime, Calendar calendar, int currentYear, int value) {
        if (value == 0) {
            return LocaleController.getString("MessageScheduleToday", R.string.MessageScheduleToday);
        }
        long date = (((long) value) * 86400000) + currentTime;
        calendar.setTimeInMillis(date);
        int year = calendar.get(1);
        if (year == currentYear) {
            return LocaleController.getInstance().formatterScheduleDay.format(date);
        }
        return LocaleController.getInstance().formatterScheduleYear.format(date);
    }

    static /* synthetic */ void lambda$createScheduleDatePickerDialog$26(boolean[] canceled, boolean reminder, NumberPicker dayPicker, NumberPicker hourPicker, NumberPicker minutePicker, Calendar calendar, ScheduleDatePickerDelegate datePickerDelegate, BottomSheet.Builder builder, View v) {
        canceled[0] = false;
        boolean setSeconds = checkScheduleDate(null, reminder, dayPicker, hourPicker, minutePicker);
        calendar.setTimeInMillis(System.currentTimeMillis() + (((long) dayPicker.getValue()) * 24 * 3600 * 1000));
        calendar.set(11, hourPicker.getValue());
        calendar.set(12, minutePicker.getValue());
        if (setSeconds) {
            calendar.set(13, 0);
        }
        datePickerDelegate.didSelectDate(true, (int) (calendar.getTimeInMillis() / 1000));
        builder.getDismissRunnable().run();
    }

    static /* synthetic */ void lambda$createScheduleDatePickerDialog$27(Runnable cancelRunnable, boolean[] canceled, DialogInterface dialog) {
        if (cancelRunnable != null && canceled[0]) {
            cancelRunnable.run();
        }
    }

    public static Dialog createMuteAlert(Context context, final long dialog_id) {
        if (context == null) {
            return null;
        }
        BottomSheet.Builder builder = new BottomSheet.Builder(context);
        builder.setTitle(LocaleController.getString("Notifications", R.string.Notifications));
        CharSequence[] items = {LocaleController.formatString("MuteFor", R.string.MuteFor, LocaleController.formatPluralString("Hours", 1)), LocaleController.formatString("MuteFor", R.string.MuteFor, LocaleController.formatPluralString("Hours", 8)), LocaleController.formatString("MuteFor", R.string.MuteFor, LocaleController.formatPluralString("Days", 2)), LocaleController.getString("MuteDisable", R.string.MuteDisable)};
        builder.setItems(items, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$y-Pa6vrE-YrMxyUdoR_x7oKX2hQ
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                AlertsCreator.lambda$createMuteAlert$28(dialog_id, dialogInterface, i);
            }
        });
        return builder.create();
    }

    static /* synthetic */ void lambda$createMuteAlert$28(long dialog_id, DialogInterface dialogInterface, int i) {
        int setting;
        if (i == 0) {
            setting = 0;
        } else if (i == 1) {
            setting = 1;
        } else if (i == 2) {
            setting = 2;
        } else {
            setting = 3;
        }
        NotificationsController.getInstance(UserConfig.selectedAccount).setDialogNotificationsSettings(dialog_id, setting);
    }

    public static void createReportAlert(Context context, final long dialog_id, final int messageId, final BaseFragment parentFragment) {
        if (context == null || parentFragment == null) {
            return;
        }
        BottomSheet.Builder builder = new BottomSheet.Builder(context);
        builder.setTitle(LocaleController.getString("ReportChat", R.string.ReportChat));
        CharSequence[] items = {LocaleController.getString("ReportChatSpam", R.string.ReportChatSpam), LocaleController.getString("ReportChatViolence", R.string.ReportChatViolence), LocaleController.getString("ReportChatChild", R.string.ReportChatChild), LocaleController.getString("ReportChatPornography", R.string.ReportChatPornography), LocaleController.getString("ReportChatOther", R.string.ReportChatOther)};
        builder.setItems(items, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$aElJPuSZhgaSLCV8iZwiJ5wnh7I
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                AlertsCreator.lambda$createReportAlert$30(dialog_id, messageId, parentFragment, dialogInterface, i);
            }
        });
        BottomSheet sheet = builder.create();
        parentFragment.showDialog(sheet);
    }

    static /* synthetic */ void lambda$createReportAlert$30(long dialog_id, int messageId, BaseFragment parentFragment, DialogInterface dialogInterface, int i) {
        TLObject req;
        if (i == 4) {
            Bundle args = new Bundle();
            args.putLong("dialog_id", dialog_id);
            args.putLong("message_id", messageId);
            parentFragment.presentFragment(new ReportOtherActivity(args));
            return;
        }
        TLRPC.InputPeer peer = MessagesController.getInstance(UserConfig.selectedAccount).getInputPeer((int) dialog_id);
        if (messageId != 0) {
            TLRPC.TL_messages_report request = new TLRPC.TL_messages_report();
            request.peer = peer;
            request.id.add(Integer.valueOf(messageId));
            if (i == 0) {
                request.reason = new TLRPC.TL_inputReportReasonSpam();
            } else if (i == 1) {
                request.reason = new TLRPC.TL_inputReportReasonViolence();
            } else if (i == 2) {
                request.reason = new TLRPC.TL_inputReportReasonChildAbuse();
            } else if (i == 3) {
                request.reason = new TLRPC.TL_inputReportReasonPornography();
            }
            req = request;
        } else {
            TLRPC.TL_account_reportPeer request2 = new TLRPC.TL_account_reportPeer();
            request2.peer = peer;
            if (i == 0) {
                request2.reason = new TLRPC.TL_inputReportReasonSpam();
            } else if (i == 1) {
                request2.reason = new TLRPC.TL_inputReportReasonViolence();
            } else if (i == 2) {
                request2.reason = new TLRPC.TL_inputReportReasonChildAbuse();
            } else if (i == 3) {
                request2.reason = new TLRPC.TL_inputReportReasonPornography();
            }
            req = request2;
        }
        ConnectionsManager.getInstance(UserConfig.selectedAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$Sn4Adc0W4qLE5C7X0VtfC3Pf1n4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AlertsCreator.lambda$null$29(tLObject, tL_error);
            }
        });
        ToastUtils.show(R.string.ReportChatSent);
    }

    static /* synthetic */ void lambda$null$29(TLObject response, TLRPC.TL_error error) {
    }

    private static String getFloodWaitString(String error) {
        String timeString;
        int time = Utilities.parseInt(error).intValue();
        if (time < 60) {
            timeString = LocaleController.formatPluralString("Seconds", time);
        } else {
            timeString = LocaleController.formatPluralString("Minutes", time / 60);
        }
        return LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString);
    }

    public static void showFloodWaitAlert(String error, BaseFragment fragment) {
        String timeString;
        if (error == null || !error.startsWith("FLOOD_WAIT") || fragment == null || fragment.getParentActivity() == null) {
            return;
        }
        int time = Utilities.parseInt(error).intValue();
        if (time < 60) {
            timeString = LocaleController.formatPluralString("Seconds", time);
        } else {
            timeString = LocaleController.formatPluralString("Minutes", time / 60);
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(fragment.getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        fragment.showDialog(builder.create(), true, null);
    }

    public static void showSendMediaAlert(int result, BaseFragment fragment) {
        if (result == 0) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(fragment.getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        if (result == 1) {
            builder.setMessage(LocaleController.getString("ErrorSendRestrictedStickers", R.string.ErrorSendRestrictedStickers));
        } else if (result == 2) {
            builder.setMessage(LocaleController.getString("ErrorSendRestrictedMedia", R.string.ErrorSendRestrictedMedia));
        } else if (result == 3) {
            builder.setMessage(LocaleController.getString("ErrorSendRestrictedPolls", R.string.ErrorSendRestrictedPolls));
        } else if (result == 4) {
            builder.setMessage(LocaleController.getString("ErrorSendRestrictedStickersAll", R.string.ErrorSendRestrictedStickersAll));
        } else if (result == 5) {
            builder.setMessage(LocaleController.getString("ErrorSendRestrictedMediaAll", R.string.ErrorSendRestrictedMediaAll));
        } else if (result == 6) {
            builder.setMessage(LocaleController.getString("ErrorSendRestrictedPollsAll", R.string.ErrorSendRestrictedPollsAll));
        }
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        fragment.showDialog(builder.create(), true, null);
    }

    public static void showAddUserAlert(String error, final BaseFragment fragment, boolean isChannel, TLObject request) {
        AlertDialog.Builder builder;
        if (error == null || fragment == null || fragment.getParentActivity() == null) {
            return;
        }
        builder = new AlertDialog.Builder(fragment.getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        switch (error) {
            case "PEER_FLOOD":
                builder.setMessage(LocaleController.getString("NobodyLikesSpam2", R.string.NobodyLikesSpam2));
                builder.setNegativeButton(LocaleController.getString("MoreInfo", R.string.MoreInfo), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$cUGJjkFEh4FvcEu80K5rNbNIvy8
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        BaseFragment baseFragment = fragment;
                        MessagesController.getInstance(baseFragment.getCurrentAccount()).openByUserName("spambot", baseFragment, 1);
                    }
                });
                break;
            case "USER_BLOCKED":
            case "USER_BOT":
            case "USER_ID_INVALID":
                if (isChannel) {
                    builder.setMessage(LocaleController.getString("ChannelUserCantAdd", R.string.ChannelUserCantAdd));
                    break;
                } else {
                    builder.setMessage(LocaleController.getString("GroupUserCantAdd", R.string.GroupUserCantAdd));
                    break;
                }
                break;
            case "USERS_TOO_MUCH":
                if (isChannel) {
                    builder.setMessage(LocaleController.getString("ChannelUserAddLimit", R.string.ChannelUserAddLimit));
                    break;
                } else {
                    builder.setMessage(LocaleController.getString("GroupUserAddLimit", R.string.GroupUserAddLimit));
                    break;
                }
                break;
            case "USER_NOT_MUTUAL_CONTACT":
                if (isChannel) {
                    builder.setMessage(LocaleController.getString("ChannelUserLeftError", R.string.ChannelUserLeftError));
                    break;
                } else {
                    builder.setMessage(LocaleController.getString("GroupUserLeftError", R.string.GroupUserLeftError));
                    break;
                }
                break;
            case "ADMINS_TOO_MUCH":
                if (isChannel) {
                    builder.setMessage(LocaleController.getString("ChannelUserCantAdmin", R.string.ChannelUserCantAdmin));
                    break;
                } else {
                    builder.setMessage(LocaleController.getString("GroupUserCantAdmin", R.string.GroupUserCantAdmin));
                    break;
                }
                break;
            case "BOTS_TOO_MUCH":
                if (isChannel) {
                    builder.setMessage(LocaleController.getString("ChannelUserCantBot", R.string.ChannelUserCantBot));
                    break;
                } else {
                    builder.setMessage(LocaleController.getString("GroupUserCantBot", R.string.GroupUserCantBot));
                    break;
                }
                break;
            case "USER_PRIVACY_RESTRICTED":
                if (isChannel) {
                    builder.setMessage(LocaleController.getString("InviteToChannelError", R.string.InviteToChannelError));
                    break;
                } else {
                    builder.setMessage(LocaleController.getString("InviteToGroupError", R.string.InviteToGroupError));
                    break;
                }
                break;
            case "USERS_TOO_FEW":
                builder.setMessage(LocaleController.getString("CreateGroupError", R.string.CreateGroupError));
                break;
            case "USER_RESTRICTED":
                builder.setMessage(LocaleController.getString("UserRestricted", R.string.UserRestricted));
                break;
            case "YOU_BLOCKED_USER":
                builder.setMessage(LocaleController.getString("YouBlockedUser", R.string.YouBlockedUser));
                break;
            case "CHAT_ADMIN_BAN_REQUIRED":
            case "USER_KICKED":
                builder.setMessage(LocaleController.getString("AddAdminErrorBlacklisted", R.string.AddAdminErrorBlacklisted));
                break;
            case "CHAT_ADMIN_INVITE_REQUIRED":
                builder.setMessage(LocaleController.getString("AddAdminErrorNotAMember", R.string.AddAdminErrorNotAMember));
                break;
            case "USER_ADMIN_INVALID":
                builder.setMessage(LocaleController.getString("AddBannedErrorAdmin", R.string.AddBannedErrorAdmin));
                break;
            case "CHANNELS_ADMIN_PUBLIC_TOO_MUCH":
                builder.setMessage(LocaleController.getString("PublicChannelsTooMuch", R.string.PublicChannelsTooMuch));
                break;
            case "CHANNELS_ADMIN_LOCATED_TOO_MUCH":
                builder.setMessage(LocaleController.getString("LocatedChannelsTooMuch", R.string.LocatedChannelsTooMuch));
                break;
            case "CHANNELS_TOO_MUCH":
                if (request instanceof TLRPC.TL_channels_createChannel) {
                    builder.setMessage(LocaleController.getString("ChannelTooMuch", R.string.ChannelTooMuch));
                    break;
                } else {
                    builder.setMessage(LocaleController.getString("ChannelTooMuchJoin", R.string.ChannelTooMuchJoin));
                    break;
                }
                break;
            default:
                builder.setMessage(LocaleController.getString("ErrorOccurred", R.string.ErrorOccurred) + ShellAdbUtils.COMMAND_LINE_END + error);
                break;
        }
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        fragment.showDialog(builder.create(), true, null);
    }

    public static Dialog createColorSelectDialog(Activity parentActivity, final long dialog_id, final int globalType, final Runnable onSelect) {
        int currentColor;
        SharedPreferences preferences = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        if (dialog_id != 0) {
            if (preferences.contains("color_" + dialog_id)) {
                currentColor = preferences.getInt("color_" + dialog_id, -16776961);
            } else if (((int) dialog_id) < 0) {
                currentColor = preferences.getInt("GroupLed", -16776961);
            } else {
                int currentColor2 = preferences.getInt("MessagesLed", -16776961);
                currentColor = currentColor2;
            }
        } else if (globalType == 1) {
            currentColor = preferences.getInt("MessagesLed", -16776961);
        } else if (globalType == 0) {
            currentColor = preferences.getInt("GroupLed", -16776961);
        } else {
            currentColor = preferences.getInt("ChannelLed", -16776961);
        }
        final LinearLayout linearLayout = new LinearLayout(parentActivity);
        linearLayout.setOrientation(1);
        String[] descriptions = {LocaleController.getString("ColorRed", R.string.ColorRed), LocaleController.getString("ColorOrange", R.string.ColorOrange), LocaleController.getString("ColorYellow", R.string.ColorYellow), LocaleController.getString("ColorGreen", R.string.ColorGreen), LocaleController.getString("ColorCyan", R.string.ColorCyan), LocaleController.getString("ColorBlue", R.string.ColorBlue), LocaleController.getString("ColorViolet", R.string.ColorViolet), LocaleController.getString("ColorPink", R.string.ColorPink), LocaleController.getString("ColorWhite", R.string.ColorWhite)};
        final int[] selectedColor = {currentColor};
        int a = 0;
        for (int i = 9; a < i; i = 9) {
            RadioColorCell cell = new RadioColorCell(parentActivity);
            cell.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f), 0);
            cell.setTag(Integer.valueOf(a));
            cell.setCheckColor(TextColorCell.colors[a], TextColorCell.colors[a]);
            cell.setTextAndValue(descriptions[a], currentColor == TextColorCell.colorsToSave[a]);
            linearLayout.addView(cell);
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$w7T1rLeTnk-bSdYQ9jIzjYt6Nhk
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    AlertsCreator.lambda$createColorSelectDialog$32(linearLayout, selectedColor, view);
                }
            });
            a++;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(parentActivity);
        builder.setTitle(LocaleController.getString("LedColor", R.string.LedColor));
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("Set", R.string.Set), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$W0kw1DZx658tiwnOrybOqIGFON4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i2) {
                AlertsCreator.lambda$createColorSelectDialog$33(dialog_id, selectedColor, globalType, onSelect, dialogInterface, i2);
            }
        });
        builder.setNeutralButton(LocaleController.getString("LedDisabled", R.string.LedDisabled), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$2TZA06U-IBoEZTDcYoxpMTxEgR4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i2) {
                AlertsCreator.lambda$createColorSelectDialog$34(dialog_id, globalType, onSelect, dialogInterface, i2);
            }
        });
        if (dialog_id != 0) {
            builder.setNegativeButton(LocaleController.getString("Default", R.string.Default), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$A1DyqZM9bukPEr8xSDb43n8NZ6g
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i2) {
                    AlertsCreator.lambda$createColorSelectDialog$35(dialog_id, onSelect, dialogInterface, i2);
                }
            });
        }
        return builder.create();
    }

    static /* synthetic */ void lambda$createColorSelectDialog$32(LinearLayout linearLayout, int[] selectedColor, View v) {
        int count = linearLayout.getChildCount();
        int a1 = 0;
        while (true) {
            boolean z = false;
            if (a1 < count) {
                RadioColorCell cell1 = (RadioColorCell) linearLayout.getChildAt(a1);
                if (cell1 == v) {
                    z = true;
                }
                cell1.setChecked(z, true);
                a1++;
            } else {
                selectedColor[0] = TextColorCell.colorsToSave[((Integer) v.getTag()).intValue()];
                return;
            }
        }
    }

    static /* synthetic */ void lambda$createColorSelectDialog$33(long dialog_id, int[] selectedColor, int globalType, Runnable onSelect, DialogInterface dialogInterface, int which) {
        SharedPreferences preferences1 = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        SharedPreferences.Editor editor = preferences1.edit();
        if (dialog_id != 0) {
            editor.putInt("color_" + dialog_id, selectedColor[0]);
        } else if (globalType == 1) {
            editor.putInt("MessagesLed", selectedColor[0]);
        } else if (globalType == 0) {
            editor.putInt("GroupLed", selectedColor[0]);
        } else {
            editor.putInt("ChannelLed", selectedColor[0]);
        }
        editor.commit();
        if (onSelect != null) {
            onSelect.run();
        }
    }

    static /* synthetic */ void lambda$createColorSelectDialog$34(long dialog_id, int globalType, Runnable onSelect, DialogInterface dialog, int which) {
        SharedPreferences preferences12 = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        SharedPreferences.Editor editor = preferences12.edit();
        if (dialog_id != 0) {
            editor.putInt("color_" + dialog_id, 0);
        } else if (globalType == 1) {
            editor.putInt("MessagesLed", 0);
        } else if (globalType == 0) {
            editor.putInt("GroupLed", 0);
        } else {
            editor.putInt("ChannelLed", 0);
        }
        editor.commit();
        if (onSelect != null) {
            onSelect.run();
        }
    }

    static /* synthetic */ void lambda$createColorSelectDialog$35(long dialog_id, Runnable onSelect, DialogInterface dialog, int which) {
        SharedPreferences preferences13 = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        SharedPreferences.Editor editor = preferences13.edit();
        editor.remove("color_" + dialog_id);
        editor.commit();
        if (onSelect != null) {
            onSelect.run();
        }
    }

    public static Dialog createVibrationSelectDialog(Activity parentActivity, long dialog_id, boolean globalGroup, boolean globalAll, Runnable onSelect) {
        String prefix;
        if (dialog_id != 0) {
            prefix = "vibrate_";
        } else {
            prefix = globalGroup ? "vibrate_group" : "vibrate_messages";
        }
        return createVibrationSelectDialog(parentActivity, dialog_id, prefix, onSelect);
    }

    public static Dialog createVibrationSelectDialog(Activity parentActivity, final long dialog_id, final String prefKeyPrefix, final Runnable onSelect) {
        String[] descriptions;
        Activity activity = parentActivity;
        SharedPreferences preferences = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        final int[] selected = new int[1];
        int i = 0;
        if (dialog_id != 0) {
            selected[0] = preferences.getInt(prefKeyPrefix + dialog_id, 0);
            if (selected[0] == 3) {
                selected[0] = 2;
            } else if (selected[0] == 2) {
                selected[0] = 3;
            }
            descriptions = new String[]{LocaleController.getString("VibrationDefault", R.string.VibrationDefault), LocaleController.getString("Short", R.string.Short), LocaleController.getString("Long", R.string.Long), LocaleController.getString("VibrationDisabled", R.string.VibrationDisabled)};
        } else {
            selected[0] = preferences.getInt(prefKeyPrefix, 0);
            if (selected[0] == 0) {
                selected[0] = 1;
            } else if (selected[0] == 1) {
                selected[0] = 2;
            } else if (selected[0] == 2) {
                selected[0] = 0;
            }
            descriptions = new String[]{LocaleController.getString("VibrationDisabled", R.string.VibrationDisabled), LocaleController.getString("VibrationDefault", R.string.VibrationDefault), LocaleController.getString("Short", R.string.Short), LocaleController.getString("Long", R.string.Long), LocaleController.getString("OnlyIfSilent", R.string.OnlyIfSilent)};
        }
        LinearLayout linearLayout = new LinearLayout(activity);
        linearLayout.setOrientation(1);
        final AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        int a = 0;
        while (a < descriptions.length) {
            RadioColorCell cell = new RadioColorCell(activity);
            cell.setPadding(AndroidUtilities.dp(4.0f), i, AndroidUtilities.dp(4.0f), i);
            cell.setTag(Integer.valueOf(a));
            cell.setCheckColor(Theme.getColor(Theme.key_radioBackground), Theme.getColor(Theme.key_dialogRadioBackgroundChecked));
            cell.setTextAndValue(descriptions[a], selected[i] == a);
            linearLayout.addView(cell);
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$uu9KGSStyUTaNYMNLAJxyiO0_cg
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    AlertsCreator.lambda$createVibrationSelectDialog$36(selected, dialog_id, prefKeyPrefix, builder, onSelect, view);
                }
            });
            a++;
            i = 0;
            activity = parentActivity;
        }
        builder.setTitle(LocaleController.getString("Vibrate", R.string.Vibrate));
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        return builder.create();
    }

    static /* synthetic */ void lambda$createVibrationSelectDialog$36(int[] selected, long dialog_id, String prefKeyPrefix, AlertDialog.Builder builder, Runnable onSelect, View v) {
        selected[0] = ((Integer) v.getTag()).intValue();
        SharedPreferences preferences1 = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        SharedPreferences.Editor editor = preferences1.edit();
        if (dialog_id != 0) {
            if (selected[0] == 0) {
                editor.putInt(prefKeyPrefix + dialog_id, 0);
            } else if (selected[0] == 1) {
                editor.putInt(prefKeyPrefix + dialog_id, 1);
            } else if (selected[0] != 2) {
                if (selected[0] == 3) {
                    editor.putInt(prefKeyPrefix + dialog_id, 2);
                }
            } else {
                editor.putInt(prefKeyPrefix + dialog_id, 3);
            }
        } else if (selected[0] == 0) {
            editor.putInt(prefKeyPrefix, 2);
        } else if (selected[0] == 1) {
            editor.putInt(prefKeyPrefix, 0);
        } else if (selected[0] != 2) {
            if (selected[0] == 3) {
                editor.putInt(prefKeyPrefix, 3);
            } else if (selected[0] == 4) {
                editor.putInt(prefKeyPrefix, 4);
            }
        } else {
            editor.putInt(prefKeyPrefix, 1);
        }
        editor.commit();
        builder.getDismissRunnable().run();
        if (onSelect != null) {
            onSelect.run();
        }
    }

    public static Dialog createLocationUpdateDialog(Activity parentActivity, TLRPC.User user, final MessagesStorage.IntCallback callback) {
        final int[] selected = new int[1];
        String[] descriptions = {LocaleController.getString("SendLiveLocationFor15m", R.string.SendLiveLocationFor15m), LocaleController.getString("SendLiveLocationFor1h", R.string.SendLiveLocationFor1h), LocaleController.getString("SendLiveLocationFor8h", R.string.SendLiveLocationFor8h)};
        final LinearLayout linearLayout = new LinearLayout(parentActivity);
        linearLayout.setOrientation(1);
        TextView titleTextView = new TextView(parentActivity);
        if (user != null) {
            titleTextView.setText(LocaleController.formatString("LiveLocationAlertPrivate", R.string.LiveLocationAlertPrivate, UserObject.getFirstName(user)));
        } else {
            titleTextView.setText(LocaleController.getString("LiveLocationAlertGroup", R.string.LiveLocationAlertGroup));
        }
        titleTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        titleTextView.setTextSize(1, 16.0f);
        titleTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        linearLayout.addView(titleTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 24, 0, 24, 8));
        int a = 0;
        while (a < descriptions.length) {
            RadioColorCell cell = new RadioColorCell(parentActivity);
            cell.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f), 0);
            cell.setTag(Integer.valueOf(a));
            cell.setCheckColor(Theme.getColor(Theme.key_radioBackground), Theme.getColor(Theme.key_dialogRadioBackgroundChecked));
            cell.setTextAndValue(descriptions[a], selected[0] == a);
            linearLayout.addView(cell);
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$qunTL0Pq38i5WIySbCEfqJLcAEE
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    AlertsCreator.lambda$createLocationUpdateDialog$37(selected, linearLayout, view);
                }
            });
            a++;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(parentActivity);
        builder.setTopImage(new ShareLocationDrawable(parentActivity, 0), Theme.getColor(Theme.key_dialogTopBackground));
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("ShareFile", R.string.ShareFile), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$0-Xnd-UzArNTBI1nu1HF91EigKk
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                AlertsCreator.lambda$createLocationUpdateDialog$38(selected, callback, dialogInterface, i);
            }
        });
        builder.setNeutralButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        return builder.create();
    }

    static /* synthetic */ void lambda$createLocationUpdateDialog$37(int[] selected, LinearLayout linearLayout, View v) {
        int num = ((Integer) v.getTag()).intValue();
        selected[0] = num;
        int count = linearLayout.getChildCount();
        for (int a1 = 0; a1 < count; a1++) {
            View child = linearLayout.getChildAt(a1);
            if (child instanceof RadioColorCell) {
                ((RadioColorCell) child).setChecked(child == v, true);
            }
        }
    }

    static /* synthetic */ void lambda$createLocationUpdateDialog$38(int[] selected, MessagesStorage.IntCallback callback, DialogInterface dialog, int which) {
        int time;
        if (selected[0] == 0) {
            time = 900;
        } else {
            int time2 = selected[0];
            if (time2 == 1) {
                time = 3600;
            } else {
                time = 28800;
            }
        }
        callback.run(time);
    }

    public static AlertDialog.Builder createContactsPermissionDialog(Activity parentActivity, final MessagesStorage.IntCallback callback) {
        AlertDialog.Builder builder = new AlertDialog.Builder(parentActivity);
        builder.setTopImage(R.drawable.permissions_contacts, Theme.getColor(Theme.key_dialogTopBackground));
        builder.setMessage(AndroidUtilities.replaceTags(LocaleController.getString("ContactsPermissionAlert", R.string.ContactsPermissionAlert)));
        builder.setPositiveButton(LocaleController.getString("ContactsPermissionAlertContinue", R.string.ContactsPermissionAlertContinue), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$bec1yGwSX81fsXFS7IlIHQ2lTro
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                callback.run(1);
            }
        });
        builder.setNegativeButton(LocaleController.getString("ContactsPermissionAlertNotNow", R.string.ContactsPermissionAlertNotNow), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$MVwxivOht7XyfMDIUW2DS-B0ETc
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                callback.run(0);
            }
        });
        return builder;
    }

    public static Dialog createFreeSpaceDialog(final LaunchActivity parentActivity) {
        final int[] selected = new int[1];
        if (SharedConfig.keepMedia == 2) {
            selected[0] = 3;
        } else if (SharedConfig.keepMedia == 0) {
            selected[0] = 1;
        } else if (SharedConfig.keepMedia == 1) {
            selected[0] = 2;
        } else if (SharedConfig.keepMedia == 3) {
            selected[0] = 0;
        }
        String[] descriptions = {LocaleController.formatPluralString("Days", 3), LocaleController.formatPluralString("Weeks", 1), LocaleController.formatPluralString("Months", 1), LocaleController.getString("LowDiskSpaceNeverRemove", R.string.LowDiskSpaceNeverRemove)};
        final LinearLayout linearLayout = new LinearLayout(parentActivity);
        linearLayout.setOrientation(1);
        TextView titleTextView = new TextView(parentActivity);
        titleTextView.setText(LocaleController.getString("LowDiskSpaceTitle2", R.string.LowDiskSpaceTitle2));
        titleTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        titleTextView.setTextSize(1, 16.0f);
        titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        titleTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        linearLayout.addView(titleTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 24, 0, 24, 8));
        int a = 0;
        while (a < descriptions.length) {
            RadioColorCell cell = new RadioColorCell(parentActivity);
            cell.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f), 0);
            cell.setTag(Integer.valueOf(a));
            cell.setCheckColor(Theme.getColor(Theme.key_radioBackground), Theme.getColor(Theme.key_dialogRadioBackgroundChecked));
            cell.setTextAndValue(descriptions[a], selected[0] == a);
            linearLayout.addView(cell);
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$_cyYihpI49BRFT6ZToHxqt6ETvQ
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    AlertsCreator.lambda$createFreeSpaceDialog$41(selected, linearLayout, view);
                }
            });
            a++;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(parentActivity);
        builder.setTitle(LocaleController.getString("LowDiskSpaceTitle", R.string.LowDiskSpaceTitle));
        builder.setMessage(LocaleController.getString("LowDiskSpaceMessage", R.string.LowDiskSpaceMessage));
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$HgjDgRWPeGf88KoCafW-yA2kqSU
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                SharedConfig.setKeepMedia(selected[0]);
            }
        });
        builder.setNeutralButton(LocaleController.getString("ClearMediaCache", R.string.ClearMediaCache), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$sN-uE32x_nOfqUveoR_RLWLA_YQ
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                parentActivity.lambda$runLinkRequest$26$LaunchActivity(new CacheControlActivity());
            }
        });
        return builder.create();
    }

    static /* synthetic */ void lambda$createFreeSpaceDialog$41(int[] selected, LinearLayout linearLayout, View v) {
        int num = ((Integer) v.getTag()).intValue();
        if (num == 0) {
            selected[0] = 3;
        } else if (num == 1) {
            selected[0] = 0;
        } else if (num == 2) {
            selected[0] = 1;
        } else if (num == 3) {
            selected[0] = 2;
        }
        int count = linearLayout.getChildCount();
        for (int a1 = 0; a1 < count; a1++) {
            View child = linearLayout.getChildAt(a1);
            if (child instanceof RadioColorCell) {
                ((RadioColorCell) child).setChecked(child == v, true);
            }
        }
    }

    public static Dialog createPrioritySelectDialog(Activity parentActivity, final long dialog_id, final int globalType, final Runnable onSelect) {
        String[] descriptions;
        Activity activity = parentActivity;
        final SharedPreferences preferences = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        final int[] selected = new int[1];
        int i = 0;
        if (dialog_id != 0) {
            selected[0] = preferences.getInt("priority_" + dialog_id, 3);
            if (selected[0] == 3) {
                selected[0] = 0;
            } else if (selected[0] == 4) {
                selected[0] = 1;
            } else if (selected[0] == 5) {
                selected[0] = 2;
            } else if (selected[0] == 0) {
                selected[0] = 3;
            } else {
                selected[0] = 4;
            }
            descriptions = new String[]{LocaleController.getString("NotificationsPrioritySettings", R.string.NotificationsPrioritySettings), LocaleController.getString("NotificationsPriorityLow", R.string.NotificationsPriorityLow), LocaleController.getString("NotificationsPriorityMedium", R.string.NotificationsPriorityMedium), LocaleController.getString("NotificationsPriorityHigh", R.string.NotificationsPriorityHigh), LocaleController.getString("NotificationsPriorityUrgent", R.string.NotificationsPriorityUrgent)};
        } else {
            if (dialog_id == 0) {
                if (globalType == 1) {
                    selected[0] = preferences.getInt("priority_messages", 1);
                } else if (globalType == 0) {
                    selected[0] = preferences.getInt("priority_group", 1);
                } else if (globalType == 2) {
                    selected[0] = preferences.getInt("priority_channel", 1);
                }
            }
            if (selected[0] == 4) {
                selected[0] = 0;
            } else if (selected[0] == 5) {
                selected[0] = 1;
            } else if (selected[0] == 0) {
                selected[0] = 2;
            } else {
                selected[0] = 3;
            }
            descriptions = new String[]{LocaleController.getString("NotificationsPriorityLow", R.string.NotificationsPriorityLow), LocaleController.getString("NotificationsPriorityMedium", R.string.NotificationsPriorityMedium), LocaleController.getString("NotificationsPriorityHigh", R.string.NotificationsPriorityHigh), LocaleController.getString("NotificationsPriorityUrgent", R.string.NotificationsPriorityUrgent)};
        }
        LinearLayout linearLayout = new LinearLayout(activity);
        linearLayout.setOrientation(1);
        final AlertDialog.Builder builder = new AlertDialog.Builder(activity);
        int a = 0;
        while (a < descriptions.length) {
            RadioColorCell cell = new RadioColorCell(activity);
            cell.setPadding(AndroidUtilities.dp(4.0f), i, AndroidUtilities.dp(4.0f), i);
            cell.setTag(Integer.valueOf(a));
            cell.setCheckColor(Theme.getColor(Theme.key_radioBackground), Theme.getColor(Theme.key_dialogRadioBackgroundChecked));
            cell.setTextAndValue(descriptions[a], selected[i] == a);
            linearLayout.addView(cell);
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$57u1fwyLyHrCqlC8pXSDHTnm674
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    AlertsCreator.lambda$createPrioritySelectDialog$44(selected, dialog_id, globalType, preferences, builder, onSelect, view);
                }
            });
            a++;
            i = 0;
            activity = parentActivity;
            linearLayout = linearLayout;
        }
        builder.setTitle(LocaleController.getString("NotificationsImportance", R.string.NotificationsImportance));
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        return builder.create();
    }

    static /* synthetic */ void lambda$createPrioritySelectDialog$44(int[] selected, long dialog_id, int globalType, SharedPreferences preferences, AlertDialog.Builder builder, Runnable onSelect, View v) {
        int option;
        int option2;
        selected[0] = ((Integer) v.getTag()).intValue();
        SharedPreferences preferences1 = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        SharedPreferences.Editor editor = preferences1.edit();
        if (dialog_id != 0) {
            if (selected[0] == 0) {
                option2 = 3;
            } else if (selected[0] != 1) {
                if (selected[0] == 2) {
                    option2 = 5;
                } else {
                    int option3 = selected[0];
                    if (option3 == 3) {
                        option2 = 0;
                    } else {
                        option2 = 1;
                    }
                }
            } else {
                option2 = 4;
            }
            editor.putInt("priority_" + dialog_id, option2);
        } else {
            if (selected[0] == 0) {
                option = 4;
            } else {
                int option4 = selected[0];
                if (option4 == 1) {
                    option = 5;
                } else {
                    int option5 = selected[0];
                    if (option5 == 2) {
                        option = 0;
                    } else {
                        option = 1;
                    }
                }
            }
            if (globalType == 1) {
                editor.putInt("priority_messages", option);
                selected[0] = preferences.getInt("priority_messages", 1);
            } else if (globalType == 0) {
                editor.putInt("priority_group", option);
                selected[0] = preferences.getInt("priority_group", 1);
            } else if (globalType == 2) {
                editor.putInt("priority_channel", option);
                selected[0] = preferences.getInt("priority_channel", 1);
            }
        }
        editor.commit();
        builder.getDismissRunnable().run();
        if (onSelect != null) {
            onSelect.run();
        }
    }

    public static Dialog createPopupSelectDialog(Activity parentActivity, final int globalType, final Runnable onSelect) {
        SharedPreferences preferences = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        final int[] selected = new int[1];
        if (globalType == 1) {
            selected[0] = preferences.getInt("popupAll", 0);
        } else if (globalType == 0) {
            selected[0] = preferences.getInt("popupGroup", 0);
        } else {
            selected[0] = preferences.getInt("popupChannel", 0);
        }
        String[] descriptions = {LocaleController.getString("NoPopup", R.string.NoPopup), LocaleController.getString("OnlyWhenScreenOn", R.string.OnlyWhenScreenOn), LocaleController.getString("OnlyWhenScreenOff", R.string.OnlyWhenScreenOff), LocaleController.getString("AlwaysShowPopup", R.string.AlwaysShowPopup)};
        LinearLayout linearLayout = new LinearLayout(parentActivity);
        linearLayout.setOrientation(1);
        final AlertDialog.Builder builder = new AlertDialog.Builder(parentActivity);
        int a = 0;
        while (a < descriptions.length) {
            RadioColorCell cell = new RadioColorCell(parentActivity);
            cell.setTag(Integer.valueOf(a));
            cell.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f), 0);
            cell.setCheckColor(Theme.getColor(Theme.key_radioBackground), Theme.getColor(Theme.key_dialogRadioBackgroundChecked));
            cell.setTextAndValue(descriptions[a], selected[0] == a);
            linearLayout.addView(cell);
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$6agqyeTT-4uLWH42h6cx2GGdl08
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    AlertsCreator.lambda$createPopupSelectDialog$45(selected, globalType, builder, onSelect, view);
                }
            });
            a++;
        }
        builder.setTitle(LocaleController.getString("PopupNotification", R.string.PopupNotification));
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        return builder.create();
    }

    static /* synthetic */ void lambda$createPopupSelectDialog$45(int[] selected, int globalType, AlertDialog.Builder builder, Runnable onSelect, View v) {
        selected[0] = ((Integer) v.getTag()).intValue();
        SharedPreferences preferences1 = MessagesController.getNotificationsSettings(UserConfig.selectedAccount);
        SharedPreferences.Editor editor = preferences1.edit();
        if (globalType == 1) {
            editor.putInt("popupAll", selected[0]);
        } else if (globalType == 0) {
            editor.putInt("popupGroup", selected[0]);
        } else {
            editor.putInt("popupChannel", selected[0]);
        }
        editor.commit();
        builder.getDismissRunnable().run();
        if (onSelect != null) {
            onSelect.run();
        }
    }

    public static Dialog createSingleChoiceDialog(Activity parentActivity, String[] options, String title, int selected, final DialogInterface.OnClickListener listener) {
        LinearLayout linearLayout = new LinearLayout(parentActivity);
        linearLayout.setOrientation(1);
        final AlertDialog.Builder builder = new AlertDialog.Builder(parentActivity);
        for (int a = 0; a < options.length; a++) {
            RadioColorCell cell = new RadioColorCell(parentActivity);
            boolean z = false;
            cell.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f), 0);
            cell.setTag(Integer.valueOf(a));
            cell.setCheckColor(Theme.getColor(Theme.key_radioBackground), Theme.getColor(Theme.key_dialogRadioBackgroundChecked));
            String str = options[a];
            if (selected == a) {
                z = true;
            }
            cell.setTextAndValue(str, z);
            linearLayout.addView(cell);
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$qMqpR2LRYt8V42Hh4VL5o2PBolo
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    AlertsCreator.lambda$createSingleChoiceDialog$46(builder, listener, view);
                }
            });
        }
        builder.setTitle(title);
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        return builder.create();
    }

    static /* synthetic */ void lambda$createSingleChoiceDialog$46(AlertDialog.Builder builder, DialogInterface.OnClickListener listener, View v) {
        int sel = ((Integer) v.getTag()).intValue();
        builder.getDismissRunnable().run();
        listener.onClick(null, sel);
    }

    public static AlertDialog.Builder createTTLAlert(Context context, final TLRPC.EncryptedChat encryptedChat) {
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(LocaleController.getString("MessageLifetime", R.string.MessageLifetime));
        final NumberPicker numberPicker = new NumberPicker(context);
        numberPicker.setMinValue(0);
        numberPicker.setMaxValue(20);
        if (encryptedChat.ttl > 0 && encryptedChat.ttl < 16) {
            numberPicker.setValue(encryptedChat.ttl);
        } else if (encryptedChat.ttl == 30) {
            numberPicker.setValue(16);
        } else if (encryptedChat.ttl == 60) {
            numberPicker.setValue(17);
        } else if (encryptedChat.ttl == 3600) {
            numberPicker.setValue(18);
        } else if (encryptedChat.ttl == 86400) {
            numberPicker.setValue(19);
        } else if (encryptedChat.ttl == 604800) {
            numberPicker.setValue(20);
        } else if (encryptedChat.ttl == 0) {
            numberPicker.setValue(0);
        }
        numberPicker.setFormatter(new NumberPicker.Formatter() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$5ShetJ7LNyVtM6UPDkrJLyFoV_k
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.Formatter
            public final String format(int i) {
                return AlertsCreator.lambda$createTTLAlert$47(i);
            }
        });
        builder.setView(numberPicker);
        builder.setNegativeButton(LocaleController.getString("Done", R.string.Done), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$Xwpz3rErAnZzSrPlOwhq87JrqZM
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                AlertsCreator.lambda$createTTLAlert$48(encryptedChat, numberPicker, dialogInterface, i);
            }
        });
        return builder;
    }

    static /* synthetic */ String lambda$createTTLAlert$47(int value) {
        if (value == 0) {
            return LocaleController.getString("ShortMessageLifetimeForever", R.string.ShortMessageLifetimeForever);
        }
        if (value >= 1 && value < 16) {
            return LocaleController.formatTTLString(value);
        }
        if (value == 16) {
            return LocaleController.formatTTLString(30);
        }
        if (value == 17) {
            return LocaleController.formatTTLString(60);
        }
        if (value == 18) {
            return LocaleController.formatTTLString(3600);
        }
        if (value == 19) {
            return LocaleController.formatTTLString(86400);
        }
        if (value == 20) {
            return LocaleController.formatTTLString(604800);
        }
        return "";
    }

    static /* synthetic */ void lambda$createTTLAlert$48(TLRPC.EncryptedChat encryptedChat, NumberPicker numberPicker, DialogInterface dialog, int which) {
        int oldValue = encryptedChat.ttl;
        int which2 = numberPicker.getValue();
        if (which2 >= 0 && which2 < 16) {
            encryptedChat.ttl = which2;
        } else if (which2 == 16) {
            encryptedChat.ttl = 30;
        } else if (which2 == 17) {
            encryptedChat.ttl = 60;
        } else if (which2 == 18) {
            encryptedChat.ttl = 3600;
        } else if (which2 == 19) {
            encryptedChat.ttl = 86400;
        } else if (which2 == 20) {
            encryptedChat.ttl = 604800;
        }
        if (oldValue != encryptedChat.ttl) {
            SecretChatHelper.getInstance(UserConfig.selectedAccount).sendTTLMessage(encryptedChat, null);
            MessagesStorage.getInstance(UserConfig.selectedAccount).updateEncryptedChatTTL(encryptedChat);
        }
    }

    public static AlertDialog createAccountSelectDialog(Activity parentActivity, final AccountSelectDelegate delegate) {
        if (UserConfig.getActivatedAccountsCount() < 2) {
            return null;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(parentActivity);
        final Runnable dismissRunnable = builder.getDismissRunnable();
        final AlertDialog[] alertDialog = new AlertDialog[1];
        LinearLayout linearLayout = new LinearLayout(parentActivity);
        linearLayout.setOrientation(1);
        for (int a = 0; a < 3; a++) {
            TLRPC.User u = UserConfig.getInstance(a).getCurrentUser();
            if (u != null) {
                AccountSelectCell cell = new AccountSelectCell(parentActivity);
                cell.setAccount(a, false);
                cell.setPadding(AndroidUtilities.dp(14.0f), 0, AndroidUtilities.dp(14.0f), 0);
                cell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                linearLayout.addView(cell, LayoutHelper.createLinear(-1, 50));
                cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$2qHhGFC5xOZYUpHFPI0VO2IZFBQ
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        AlertsCreator.lambda$createAccountSelectDialog$49(alertDialog, dismissRunnable, delegate, view);
                    }
                });
            }
        }
        builder.setTitle(LocaleController.getString("SelectAccount", R.string.SelectAccount));
        builder.setView(linearLayout);
        builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        AlertDialog alertDialogCreate = builder.create();
        alertDialog[0] = alertDialogCreate;
        return alertDialogCreate;
    }

    static /* synthetic */ void lambda$createAccountSelectDialog$49(AlertDialog[] alertDialog, Runnable dismissRunnable, AccountSelectDelegate delegate, View v) {
        if (alertDialog[0] != null) {
            alertDialog[0].setOnDismissListener(null);
        }
        dismissRunnable.run();
        AccountSelectCell cell1 = (AccountSelectCell) v;
        delegate.didSelectAccount(cell1.getAccountNumber());
    }

    /* JADX WARN: Removed duplicated region for block: B:209:0x044f  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x05bd  */
    /* JADX WARN: Removed duplicated region for block: B:269:0x05ca  */
    /* JADX WARN: Removed duplicated region for block: B:280:0x061f  */
    /* JADX WARN: Removed duplicated region for block: B:286:0x0660  */
    /* JADX WARN: Removed duplicated region for block: B:293:0x0683  */
    /* JADX WARN: Removed duplicated region for block: B:295:0x0686  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x068e  */
    /* JADX WARN: Removed duplicated region for block: B:299:0x06b5  */
    /* JADX WARN: Removed duplicated region for block: B:327:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void createDeleteMessagesAlert(final im.uwrkaxlmjj.ui.actionbar.BaseFragment r49, final im.uwrkaxlmjj.tgnet.TLRPC.User r50, final im.uwrkaxlmjj.tgnet.TLRPC.Chat r51, final im.uwrkaxlmjj.tgnet.TLRPC.EncryptedChat r52, final im.uwrkaxlmjj.tgnet.TLRPC.ChatFull r53, final long r54, final im.uwrkaxlmjj.messenger.MessageObject r56, final android.util.SparseArray<im.uwrkaxlmjj.messenger.MessageObject>[] r57, final im.uwrkaxlmjj.messenger.MessageObject.GroupedMessages r58, final boolean r59, int r60, final java.lang.Runnable r61) {
        /*
            Method dump skipped, instruction units count: 1730
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.AlertsCreator.createDeleteMessagesAlert(im.uwrkaxlmjj.ui.actionbar.BaseFragment, im.uwrkaxlmjj.tgnet.TLRPC$User, im.uwrkaxlmjj.tgnet.TLRPC$Chat, im.uwrkaxlmjj.tgnet.TLRPC$EncryptedChat, im.uwrkaxlmjj.tgnet.TLRPC$ChatFull, long, im.uwrkaxlmjj.messenger.MessageObject, android.util.SparseArray[], im.uwrkaxlmjj.messenger.MessageObject$GroupedMessages, boolean, int, java.lang.Runnable):void");
    }

    static /* synthetic */ void lambda$null$50(AlertDialog[] progressDialog, TLObject response, BaseFragment fragment, TLRPC.User user, TLRPC.Chat chat, TLRPC.EncryptedChat encryptedChat, TLRPC.ChatFull chatInfo, long mergeDialogId, MessageObject selectedMessage, SparseArray[] selectedMessages, MessageObject.GroupedMessages selectedGroup, boolean scheduled, Runnable onDelete) {
        try {
            progressDialog[0].dismiss();
        } catch (Throwable th) {
        }
        progressDialog[0] = null;
        int loadType = 2;
        if (response != null) {
            TLRPC.TL_channels_channelParticipant participant = (TLRPC.TL_channels_channelParticipant) response;
            if (!(participant.participant instanceof TLRPC.TL_channelParticipantAdmin) && !(participant.participant instanceof TLRPC.TL_channelParticipantCreator)) {
                loadType = 0;
            }
        }
        createDeleteMessagesAlert(fragment, user, chat, encryptedChat, chatInfo, mergeDialogId, selectedMessage, selectedMessages, selectedGroup, scheduled, loadType, onDelete);
    }

    static /* synthetic */ void lambda$createDeleteMessagesAlert$53(AlertDialog[] progressDialog, final int currentAccount, final int requestId, BaseFragment fragment) {
        if (progressDialog[0] == null) {
            return;
        }
        progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AlertsCreator$jcZC-EwkPWASmqirClvC9uXcngc
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                ConnectionsManager.getInstance(currentAccount).cancelRequest(requestId, true);
            }
        });
        fragment.showDialog(progressDialog[0]);
    }

    static /* synthetic */ void lambda$createDeleteMessagesAlert$54(boolean[] checks, View v) {
        if (!v.isEnabled()) {
            return;
        }
        CheckBoxCell cell13 = (CheckBoxCell) v;
        Integer num1 = (Integer) cell13.getTag();
        checks[num1.intValue()] = !checks[num1.intValue()];
        cell13.setChecked(checks[num1.intValue()], true);
    }

    static /* synthetic */ void lambda$createDeleteMessagesAlert$55(boolean[] deleteForAll, View v) {
        CheckBoxCell cell12 = (CheckBoxCell) v;
        deleteForAll[0] = !deleteForAll[0];
        cell12.setChecked(deleteForAll[0], true);
    }

    static /* synthetic */ void lambda$createDeleteMessagesAlert$56(boolean[] deleteForAll, View v) {
        CheckBoxCell cell1 = (CheckBoxCell) v;
        deleteForAll[0] = !deleteForAll[0];
        cell1.setChecked(deleteForAll[0], true);
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00f7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$createDeleteMessagesAlert$58(im.uwrkaxlmjj.messenger.MessageObject r21, im.uwrkaxlmjj.messenger.MessageObject.GroupedMessages r22, im.uwrkaxlmjj.tgnet.TLRPC.EncryptedChat r23, int r24, long r25, boolean[] r27, boolean r28, android.util.SparseArray[] r29, im.uwrkaxlmjj.tgnet.TLRPC.User r30, boolean[] r31, im.uwrkaxlmjj.tgnet.TLRPC.Chat r32, im.uwrkaxlmjj.tgnet.TLRPC.ChatFull r33, java.lang.Runnable r34, android.content.DialogInterface r35, int r36) {
        /*
            Method dump skipped, instruction units count: 424
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.AlertsCreator.lambda$createDeleteMessagesAlert$58(im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.messenger.MessageObject$GroupedMessages, im.uwrkaxlmjj.tgnet.TLRPC$EncryptedChat, int, long, boolean[], boolean, android.util.SparseArray[], im.uwrkaxlmjj.tgnet.TLRPC$User, boolean[], im.uwrkaxlmjj.tgnet.TLRPC$Chat, im.uwrkaxlmjj.tgnet.TLRPC$ChatFull, java.lang.Runnable, android.content.DialogInterface, int):void");
    }

    static /* synthetic */ void lambda$null$57(TLObject response, TLRPC.TL_error error) {
    }
}
