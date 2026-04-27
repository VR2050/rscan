package im.uwrkaxlmjj.ui.hui.wallet_public.utils;

import android.content.DialogInterface;
import android.text.Html;
import android.text.TextUtils;
import com.alibaba.fastjson.parser.JSONLexer;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.constants.Constants;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletConfigBean;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import kotlin.jvm.internal.ByteCompanionObject;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletErrorUtil implements Constants {
    public static void parseErrorToast(int errorMsgKey) {
        parseErrorToast(LocaleController.getString(errorMsgKey + "", errorMsgKey));
    }

    public static void parseErrorToast(String errorMsg) {
        ToastUtils.show((CharSequence) getErrorDescription(errorMsg));
    }

    public static void parseErrorToast(int prefixOfErrorMsgKey, String errorMsg) {
        parseErrorToast(LocaleController.getString(prefixOfErrorMsgKey + "", prefixOfErrorMsgKey), errorMsg);
    }

    public static void parseErrorToast(String prefixOfErrorMsg, String errorMsg) {
        ToastUtils.show((CharSequence) getErrorDescription(prefixOfErrorMsg, errorMsg));
    }

    public static WalletDialog parseErrorDialog(Object host, int errorMsgKey) {
        return parseErrorDialog(host, LocaleController.getString(errorMsgKey + "", errorMsgKey));
    }

    public static WalletDialog parseErrorDialog(Object host, int errorMsgKey, boolean cancelable) {
        return parseErrorDialog(host, LocaleController.getString(errorMsgKey + "", errorMsgKey), cancelable);
    }

    public static WalletDialog parseErrorDialog(Object host, String errorMsg) {
        return WalletDialogUtil.showConfirmBtnWalletDialog(host, getErrorDescription(errorMsg));
    }

    public static WalletDialog parseErrorDialog(Object host, String errorMsg, boolean cancelable) {
        return WalletDialogUtil.showConfirmBtnWalletDialog(host, getErrorDescription(errorMsg), cancelable);
    }

    public static WalletDialog parseErrorDialog(Object host, String errMsg, boolean cancel, String btnText, DialogInterface.OnClickListener listener) {
        return WalletDialogUtil.showSingleBtnWalletDialog(host, getErrorDescription(errMsg), btnText, cancel, listener);
    }

    public static WalletDialog parseErrorDialog(Object host, int prefixOfErrorMsgKey, int errorMsgKey) {
        return parseErrorDialog(host, prefixOfErrorMsgKey, LocaleController.getString(errorMsgKey + "", errorMsgKey));
    }

    public static WalletDialog parseErrorDialog(Object host, int prefixOfErrorMsgKey, int errorMsgKey, boolean cancelable) {
        return parseErrorDialog(host, prefixOfErrorMsgKey, LocaleController.getString(errorMsgKey + "", errorMsgKey), cancelable);
    }

    public static WalletDialog parseErrorDialog(Object host, int prefixOfErrorMsgKey, String errorMsg) {
        return parseErrorDialog(host, LocaleController.getString(prefixOfErrorMsgKey + "", prefixOfErrorMsgKey), errorMsg);
    }

    public static WalletDialog parseErrorDialog(Object host, int prefixOfErrorMsgKey, String errorMsg, boolean cancelable) {
        return parseErrorDialog(host, LocaleController.getString(prefixOfErrorMsgKey + "", prefixOfErrorMsgKey), errorMsg, cancelable);
    }

    public static WalletDialog parseErrorDialog(Object host, String prefixOfErrorMsg, String errorMsg) {
        return WalletDialogUtil.showConfirmBtnWalletDialog(host, getErrorDescription(prefixOfErrorMsg, errorMsg), true);
    }

    public static WalletDialog parseErrorDialog(Object host, String prefixOfErrorMsg, String errorMsg, boolean cancelable) {
        return WalletDialogUtil.showConfirmBtnWalletDialog(host, getErrorDescription(prefixOfErrorMsg, errorMsg), cancelable);
    }

    public static String getErrorDescription(int errorMsgKey) {
        return getErrorDescription(LocaleController.getString(errorMsgKey + "", errorMsgKey));
    }

    public static String getErrorDescription(String errorMsg) {
        return getErrorDescription((String) null, errorMsg);
    }

    public static String getErrorDescription(int prefixOfErrorMsgKey, int errorMsgKey) {
        return getErrorDescription(prefixOfErrorMsgKey, LocaleController.getString(errorMsgKey + "", errorMsgKey));
    }

    public static String getErrorDescription(int prefixOfErrorMsgKey, String errorMsg) {
        return getErrorDescription(LocaleController.getString(prefixOfErrorMsgKey + "", prefixOfErrorMsgKey), errorMsg);
    }

    public static boolean parsePayPasswordErrorDialog(final BaseFragment fragment, String errorMsg) {
        String content;
        String confirmText;
        if (fragment == null || fragment.getParentActivity() == null) {
            return false;
        }
        boolean tag = false;
        WalletDialog dialog = new WalletDialog(fragment.getParentActivity());
        if (errorMsg != null) {
            if (errorMsg.contains("FROZEN")) {
                tag = true;
                String[] numbers = NumberUtil.getNumbersFromStr(errorMsg);
                int count = 0;
                if (numbers.length == 2) {
                    count = Integer.valueOf(numbers[1]).intValue();
                }
                if (count > 0) {
                    content = LocaleController.getString(R.string.ErrorPayPasswordAndTryAgain) + "<br/><br/>" + String.format(LocaleController.getString(R.string.YouCanEnterTimesWithColor), Integer.valueOf(count));
                    confirmText = LocaleController.getString(R.string.ForgetPassword);
                } else {
                    content = LocaleController.getString(R.string.TheAccountHasBeenFrozenWith24H);
                    confirmText = LocaleController.getString(R.string.ContactCustomerService);
                }
                dialog.setMessage(Html.fromHtml(content), true, true);
                final int finalCount = count;
                dialog.setPositiveButton(confirmText, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.wallet_public.utils.-$$Lambda$WalletErrorUtil$476MD3_6QzrOf8NsPhp2mA8F-uk
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        WalletErrorUtil.lambda$parsePayPasswordErrorDialog$0(finalCount, fragment, dialogInterface, i);
                    }
                });
            } else if ("DAY_BAND_BANK_NUMBER_OVER_LIMIT".equals(errorMsg)) {
                tag = true;
                dialog.setMessage(LocaleController.getString(R.string.NumberOfAddBankCardTodayHadExceededLimitTips));
                dialog.setPositiveButton(LocaleController.getString(R.string.OK), null);
            } else {
                dialog.setMessage(getErrorDescription(errorMsg), true, true);
            }
        }
        if (tag) {
            dialog.getNegativeButton().setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
            dialog.setNegativeButton(LocaleController.getString(R.string.Retry), null);
            fragment.showDialog(dialog);
        }
        return tag;
    }

    static /* synthetic */ void lambda$parsePayPasswordErrorDialog$0(int finalCount, BaseFragment fragment, DialogInterface dialogInterface, int i) {
        if (finalCount <= 0) {
            fragment.presentFragment(new AboutAppActivity());
        }
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public static String getErrorDescription(String prefixOfErrorMsg, String errorMsg) {
        String realErrorMsg = LocaleController.getString("ServerErrorResponseIsEmpty", R.string.ServerErrorResponseIsEmpty);
        if (errorMsg != null) {
            if (!errorMsg.contains("ACCOUNT_PASSWORD_IN_MINUTES,ERROR_TIMES,WILL_BE_FROZEN_")) {
                if (errorMsg.contains("ERROR_NO_CANCELLATION_BALANCE_GREATER_THAN_")) {
                    String[] arr = NumberUtil.getNumbersFromStr(errorMsg);
                    if (arr.length == 1) {
                        realErrorMsg = LocaleController.formatString("CancelAccountFailWithCashIsNotEmpty", R.string.CancelAccountFailWithCashIsNotEmpty, arr[0]);
                    }
                } else {
                    byte b = -1;
                    switch (errorMsg.hashCode()) {
                        case -2144635420:
                            if (errorMsg.equals("ERROR_CODE")) {
                                b = 0;
                            }
                            break;
                        case -2092522851:
                            if (errorMsg.equals("CURRENCY_TYPE_IS_EMPTY_CODE")) {
                                b = 108;
                            }
                            break;
                        case -2091299496:
                            if (errorMsg.equals("SUCCESS_RED_STATUS_INVALID_CODE")) {
                                b = 16;
                            }
                            break;
                        case -2079937259:
                            if (errorMsg.equals("ERROR_ADDRESS_NOT_NULL")) {
                                b = 92;
                            }
                            break;
                        case -2025769420:
                            if (errorMsg.equals("ERROR_NOT_SUPPORTED_PAY")) {
                                b = 79;
                            }
                            break;
                        case -1972351521:
                            if (errorMsg.equals("ERROR_TRANSFER_TO_EXIST_SUBMIT_REPEATEDLY")) {
                                b = 83;
                            }
                            break;
                        case -1968712000:
                            if (errorMsg.equals("ERROR_CASH_AMOUNT_MISMATCH")) {
                                b = 97;
                            }
                            break;
                        case -1964016177:
                            if (errorMsg.equals("ERROR_TRADELOG_ID_NOT_NULL")) {
                                b = 98;
                            }
                            break;
                        case -1961651411:
                            if (errorMsg.equals("SUCCESS_RED_STATUS_EXISTENCE_CODE")) {
                                b = 17;
                            }
                            break;
                        case -1951241795:
                            if (errorMsg.equals("ERROR_SERVICE_CHARGE_NOT_NULL")) {
                                b = 68;
                            }
                            break;
                        case -1936208949:
                            if (errorMsg.equals("TRANSFER_REPEAT_PAY_ERROR_CODE")) {
                                b = 25;
                            }
                            break;
                        case -1923611970:
                            if (errorMsg.equals("ERROR_PAY_SET_NOT_NULL")) {
                                b = 89;
                            }
                            break;
                        case -1896901538:
                            if (errorMsg.equals("AUTHENTICATE_INFO_ERR")) {
                                b = 102;
                            }
                            break;
                        case -1844978982:
                            if (errorMsg.equals("NO_USABLE_CHANNEL")) {
                                b = 116;
                            }
                            break;
                        case -1773444383:
                            if (errorMsg.equals("ERROR_DIRECTION_OF_BUSINESS_NOT_NULL")) {
                                b = 72;
                            }
                            break;
                        case -1761476232:
                            if (errorMsg.equals("TRANSFER_ACCOUNTS_UNAVAILABLE_ERROR_CODE")) {
                                b = 12;
                            }
                            break;
                        case -1675822067:
                            if (errorMsg.equals("NO_SMS_VERIFICATION_CODE")) {
                                b = 111;
                            }
                            break;
                        case -1605877014:
                            if (errorMsg.equals("DAY_BAND_BANK_NUMBER_OVER_LIMIT")) {
                                b = 125;
                            }
                            break;
                        case -1577993965:
                            if (errorMsg.equals("ERROR_RED_TYPE_NOT_NULL")) {
                                b = 58;
                            }
                            break;
                        case -1575231852:
                            if (errorMsg.equals("ERROR_INITIATOR_OR_BUYER_NOT_NULL")) {
                                b = 77;
                            }
                            break;
                        case -1549115538:
                            if (errorMsg.equals("ERROR_RECEIVER_USER_NOT_NULL")) {
                                b = 55;
                            }
                            break;
                        case -1469612725:
                            if (errorMsg.equals("SYSTEM_ERROR_NOT_SET_PAYWORD_COCE")) {
                                b = 28;
                            }
                            break;
                        case -1454959391:
                            if (errorMsg.equals("RED_UNAVAILABLE_ERROR_CODE")) {
                                b = 11;
                            }
                            break;
                        case -1449090263:
                            if (errorMsg.equals("THE_TRANSFER_HAS_BEEN_CANCELLED")) {
                                b = 119;
                            }
                            break;
                        case -1435642988:
                            if (errorMsg.equals("ERROR_AMOUNT_DOES_NOT_MATCH_CONFIRMED_AMOUNT")) {
                                b = 96;
                            }
                            break;
                        case -1349891338:
                            if (errorMsg.equals("ERROR_REMARKS_NOT_NULL")) {
                                b = 65;
                            }
                            break;
                        case -1294203302:
                            if (errorMsg.equals("PAY_PASSWORD_MAX_ACCOUNT_FROZEN")) {
                                b = 37;
                            }
                            break;
                        case -1272363335:
                            if (errorMsg.equals("SUCCESS_RED_NOT_COLLECTED_CODE")) {
                                b = 18;
                            }
                            break;
                        case -1258389000:
                            if (errorMsg.equals("THE_BANK_INFORMATION_HAS_BEEN_BOUND")) {
                                b = 107;
                            }
                            break;
                        case -1246306989:
                            if (errorMsg.equals("EFFECT_USER_INFONNOT_CODE")) {
                                b = 10;
                            }
                            break;
                        case -1232921218:
                            if (errorMsg.equals("INCONSISTENT_VALIDATION_INFORMATION_CODE")) {
                                b = 113;
                            }
                            break;
                        case -1190339722:
                            if (errorMsg.equals("ALREADY_VIP")) {
                                b = 129;
                            }
                            break;
                        case -1177453267:
                            if (errorMsg.equals("ERROR_UNIT_PRICE_NOT_NULL")) {
                                b = 67;
                            }
                            break;
                        case -1171826550:
                            if (errorMsg.equals("SUCCESS_USERINFO_INFORMATION_GROUP_CODE")) {
                                b = 23;
                            }
                            break;
                        case -1148959888:
                            if (errorMsg.equals("ERROR_USER_NOT_MATCH_CODE")) {
                                b = 9;
                            }
                            break;
                        case -1145264038:
                            if (errorMsg.equals("PARAMETER_ERROR_CODE")) {
                                b = 3;
                            }
                            break;
                        case -1123435528:
                            if (errorMsg.equals("ORDER_NOT_CANCELLED_CODE")) {
                                b = 8;
                            }
                            break;
                        case -1108080737:
                            if (errorMsg.equals("RED_MSG_NOT_EXIST")) {
                                b = 118;
                            }
                            break;
                        case -945961441:
                            if (errorMsg.equals("ERROR_RED_INFO_NOT_NULL")) {
                                b = 20;
                            }
                            break;
                        case -898271457:
                            if (errorMsg.equals("ERROR_SYSTEM_CODE_ALREADY")) {
                                b = 82;
                            }
                            break;
                        case -862586151:
                            if (errorMsg.equals("ERROR_TOTALFEE_NOT_NULL")) {
                                b = 76;
                            }
                            break;
                        case -815654167:
                            if (errorMsg.equals("REPEATED_REQUESTS")) {
                                b = 2;
                            }
                            break;
                        case -803269227:
                            if (errorMsg.equals("ErrorSendMessageTooFreq")) {
                                b = 101;
                            }
                            break;
                        case -745834116:
                            if (errorMsg.equals("BANK_NUMBER_NOT_STANDARD")) {
                                b = 122;
                            }
                            break;
                        case -739718390:
                            if (errorMsg.equals("ERROR_ORDER_TO_EXIST_SUBMIT_REPEATEDLY")) {
                                b = 85;
                            }
                            break;
                        case -734874358:
                            if (errorMsg.equals("ERROR_USER_NAME_NOT_NULL")) {
                                b = 48;
                            }
                            break;
                        case -580958708:
                            if (errorMsg.equals("SYSTEM_VERIFICATION_CODE_EXPIRED_SMS_COCE")) {
                                b = 31;
                            }
                            break;
                        case -577434663:
                            if (errorMsg.equals("NOT_SUFFICIENT_FUNDS")) {
                                b = 117;
                            }
                            break;
                        case -539680220:
                            if (errorMsg.equals("BANK_NOT_WITHDRAWAL")) {
                                b = 115;
                            }
                            break;
                        case -488853947:
                            if (errorMsg.equals("ERROR_TOTAL_AMOUNT_OF_CASH_SOLD_NOT_NULL")) {
                                b = 73;
                            }
                            break;
                        case -449813985:
                            if (errorMsg.equals("SYSTEM_VERIFICATION_ERROR_SMS_COCE")) {
                                b = 32;
                            }
                            break;
                        case -434497339:
                            if (errorMsg.equals("ERROR_IMG_TYPE_NOT_NULL")) {
                                b = 80;
                            }
                            break;
                        case -430617811:
                            if (errorMsg.equals("SYSTEM_ERROR_BANK_NO_BADING_CODE")) {
                                b = 34;
                            }
                            break;
                        case -424816978:
                            if (errorMsg.equals("ERROR_NOTALLOW_HAIR_LUCK_RED")) {
                                b = 60;
                            }
                            break;
                        case -410570710:
                            if (errorMsg.equals("SYSTEM_ERROR_BANK_NO_FROZEN_CODE")) {
                                b = 42;
                            }
                            break;
                        case -409306558:
                            if (errorMsg.equals("ERROR_TRANSACTION_AMOUNT_NOT_NULL")) {
                                b = 69;
                            }
                            break;
                        case -329865043:
                            if (errorMsg.equals("TRANSFER_NON_CANCELLING_ERROR_CODE")) {
                                b = 22;
                            }
                            break;
                        case -256279664:
                            if (errorMsg.equals("SUCCESS_RED_STATUS_COMPLETE_CODE")) {
                                b = 14;
                            }
                            break;
                        case -251524880:
                            if (errorMsg.equals("EXCEED_TRANSFER_ONCE_MAX_MONEY")) {
                                b = ByteCompanionObject.MAX_VALUE;
                            }
                            break;
                        case -232446680:
                            if (errorMsg.equals("SYSTEM_REPEAT_SMS_COCE")) {
                                b = 29;
                            }
                            break;
                        case -224509840:
                            if (errorMsg.equals("ERROR_RECEIVER_OR_SELLER_NOT_NULL")) {
                                b = 57;
                            }
                            break;
                        case -175935118:
                            if (errorMsg.equals("AUTHENTICATE_INFO_NOT_MATCH")) {
                                b = 124;
                            }
                            break;
                        case -169668534:
                            if (errorMsg.equals("ERROR_CONFIRM_PAY_PASSWORD_NOT_NULL")) {
                                b = 45;
                            }
                            break;
                        case -130358483:
                            if (errorMsg.equals("ERROR_ORDER_DOES_NOT_EXIST")) {
                                b = 86;
                            }
                            break;
                        case -130024776:
                            if (errorMsg.equals("ERROR_MERCHANT_ORDER_NUMBER_NOT_NULL")) {
                                b = 66;
                            }
                            break;
                        case -88118345:
                            if (errorMsg.equals("ERROR_NOT_SUPPORTED_PAY_SET")) {
                                b = 90;
                            }
                            break;
                        case -58040641:
                            if (errorMsg.equals("TRANSFER_CANCELLING_ERROR_CODE")) {
                                b = 24;
                            }
                            break;
                        case 21821413:
                            if (errorMsg.equals("USER_INFONNOT_CODE")) {
                                b = 4;
                            }
                            break;
                        case 41860780:
                            if (errorMsg.equals("ERROR_AMOUNT_BELOW_MINIMUM_LIMIT")) {
                                b = 64;
                            }
                            break;
                        case 89931806:
                            if (errorMsg.equals("ERROR_GRANT_TYPE_NOT_NULL")) {
                                b = 59;
                            }
                            break;
                        case 100175290:
                            if (errorMsg.equals("TOO_MANY_REQUEST")) {
                                b = 100;
                            }
                            break;
                        case 127292299:
                            if (errorMsg.equals("ERROR_GROUPS_RED_NUMBER")) {
                                b = 56;
                            }
                            break;
                        case 155378505:
                            if (errorMsg.equals("ERROR_INCONSISTENT_AMOUNT")) {
                                b = 63;
                            }
                            break;
                        case 197222107:
                            if (errorMsg.equals("ID_NUMBER_NOT_STANDARD")) {
                                b = 121;
                            }
                            break;
                        case 199708815:
                            if (errorMsg.equals("ERROR_OPENBANK_OR_BANKCODE_NOT_NULL")) {
                                b = 87;
                            }
                            break;
                        case 235405616:
                            if (errorMsg.equals("ACCOUNT_UNCERTIFIED_CODE")) {
                                b = 38;
                            }
                            break;
                        case 292411456:
                            if (errorMsg.equals("ERROR_RANDOM_TIME_NOT_NULL")) {
                                b = 52;
                            }
                            break;
                        case 343356237:
                            if (errorMsg.equals("ACCOUNT_PAY_PASSWORD_ERROR")) {
                                b = 40;
                            }
                            break;
                        case 371395673:
                            if (errorMsg.equals("ERROR_ID_CAD_NOT_NULL")) {
                                b = 49;
                            }
                            break;
                        case 505899914:
                            if (errorMsg.equals("BANK_INFO_EXISTS")) {
                                b = 114;
                            }
                            break;
                        case 598536268:
                            if (errorMsg.equals("TRANSFER_COMPLETED_ERROR_CODE")) {
                                b = 21;
                            }
                            break;
                        case 661399960:
                            if (errorMsg.equals("ERROR_FIXED_AMOUNT_NOT_NULL")) {
                                b = 62;
                            }
                            break;
                        case 677566228:
                            if (errorMsg.equals("ERROR_ACC_NUMBER_NOT_NULL")) {
                                b = 91;
                            }
                            break;
                        case 694574117:
                            if (errorMsg.equals("EXCEED_RED_PACKET_ONCE_MAX_MONEY")) {
                                b = 126;
                            }
                            break;
                        case 731241168:
                            if (errorMsg.equals("ERROR_TRANSFER_NOT_NULL")) {
                                b = 51;
                            }
                            break;
                        case 746324468:
                            if (errorMsg.equals("SYSTEM_ERROR_CODE")) {
                                b = 39;
                            }
                            break;
                        case 833588359:
                            if (errorMsg.equals("EXCLUSIVE_PLEASE_BIND_FIRST_BANKINFO")) {
                                b = 104;
                            }
                            break;
                        case 837752632:
                            if (errorMsg.equals("ERROR_VERIFICATION_CODE_NOT_NULL")) {
                                b = 47;
                            }
                            break;
                        case 840426438:
                            if (errorMsg.equals("CARRYOVER_INFO_DOES_NOT_EXIST")) {
                                b = 106;
                            }
                            break;
                        case 866398254:
                            if (errorMsg.equals("SYSTEM_UNSUPPORTED_FILE_ERROR_COCE")) {
                                b = 33;
                            }
                            break;
                        case 898444516:
                            if (errorMsg.equals("ACCOUNT_DISACCORD_AUTHENTICATION_INFORMATION_CODE")) {
                                b = 103;
                            }
                            break;
                        case 904822764:
                            if (errorMsg.equals("SUCCESS_RED_STATUS_RECEIVE_CODE")) {
                                b = 13;
                            }
                            break;
                        case 930821507:
                            if (errorMsg.equals("TYPE_IS_NOT_NULL")) {
                                b = 109;
                            }
                            break;
                        case 938682073:
                            if (errorMsg.equals("CARRYOVER_THE_TRANSFER_HAS_BEEN_RECEIVED")) {
                                b = 120;
                            }
                            break;
                        case 956012942:
                            if (errorMsg.equals("ERROR_RED_NUMBER")) {
                                b = 61;
                            }
                            break;
                        case 960863229:
                            if (errorMsg.equals("NAME_NOT_STANDARD")) {
                                b = 123;
                            }
                            break;
                        case 1050804984:
                            if (errorMsg.equals("ERROR_BANK_INFO_NOT_NULL")) {
                                b = 93;
                            }
                            break;
                        case 1077990923:
                            if (errorMsg.equals("ERROR_USER_IS_NOT_NULL")) {
                                b = 43;
                            }
                            break;
                        case 1117754157:
                            if (errorMsg.equals("ERROR_TADDITIONAL_DATA_NOT_NULL")) {
                                b = 71;
                            }
                            break;
                        case 1126260135:
                            if (errorMsg.equals("ERROR_RED_TO_EXIST_SUBMIT_REPEATEDLY")) {
                                b = 84;
                            }
                            break;
                        case 1178337426:
                            if (errorMsg.equals("ORDER_NOT_EXIST_CODE")) {
                                b = 7;
                            }
                            break;
                        case 1185352029:
                            if (errorMsg.equals("ERROR_NOT_SUPPORTED_TEMPORARILY_FUNCTION")) {
                                b = 99;
                            }
                            break;
                        case 1222472957:
                            if (errorMsg.equals("ERROR_PRODUCT_DESCRIPTION_NOT_NULL")) {
                                b = 75;
                            }
                            break;
                        case 1234557633:
                            if (errorMsg.equals("SYSTEM_SMS_NOT_SUPPORTED_COCE")) {
                                b = 110;
                            }
                            break;
                        case 1260306429:
                            if (errorMsg.equals("ERROR_ACCOUNT_SYNCHRONIZED")) {
                                b = 81;
                            }
                            break;
                        case 1335086637:
                            if (errorMsg.equals("ERROR_ILLEGAL_CODE")) {
                                b = 1;
                            }
                            break;
                        case 1407588716:
                            if (errorMsg.equals("ORDER_CANCELLED_CODE")) {
                                b = 6;
                            }
                            break;
                        case 1488864863:
                            if (errorMsg.equals("ORDER_OK_CODE")) {
                                b = 5;
                            }
                            break;
                        case 1491676330:
                            if (errorMsg.equals("SUCCESS_RED_STATUS_NUMBER_FULL_CODE")) {
                                b = 15;
                            }
                            break;
                        case 1518236069:
                            if (errorMsg.equals("ERROR_RED_NUMBER_ILLEGAL")) {
                                b = 54;
                            }
                            break;
                        case 1539334037:
                            if (errorMsg.equals("ERROR_GROUPS_NUMBER_NOT_NULL")) {
                                b = 88;
                            }
                            break;
                        case 1554846384:
                            if (errorMsg.equals("ACCOUNT_HAS_BEEN_FROZEN_CODE")) {
                                b = 36;
                            }
                            break;
                        case 1556727811:
                            if (errorMsg.equals("INSUFFICIENT")) {
                                b = ByteCompanionObject.MIN_VALUE;
                            }
                            break;
                        case 1598219258:
                            if (errorMsg.equals("BANKINFO_DOES_NOT_EXIST")) {
                                b = 105;
                            }
                            break;
                        case 1630302841:
                            if (errorMsg.equals("ERROR_ORDER_HAS_BEEN_CONFIRMED")) {
                                b = 95;
                            }
                            break;
                        case 1668633190:
                            if (errorMsg.equals("ERROR_TRADE_TYPE_NOT_NULL")) {
                                b = 78;
                            }
                            break;
                        case 1688152246:
                            if (errorMsg.equals("SYSTEM_ERROR_ACCOUNT_EXCEPTION_CODE")) {
                                b = 27;
                            }
                            break;
                        case 1713725742:
                            if (errorMsg.equals("THE_TRANSFER_IS_NOT_AVAILABLE")) {
                                b = JSONLexer.EOI;
                            }
                            break;
                        case 1730358686:
                            if (errorMsg.equals("ERROR_NEW_PASSWORD_IS_INCONSISTENT")) {
                                b = 46;
                            }
                            break;
                        case 1782154686:
                            if (errorMsg.equals("EXCLUSIVE_RED_NOT_COLLECTED_CODE")) {
                                b = 19;
                            }
                            break;
                        case 1783865422:
                            if (errorMsg.equals("ERROR_TEL_NOT_NULL")) {
                                b = 50;
                            }
                            break;
                        case 1853331822:
                            if (errorMsg.equals("ERROR_RANDOM_CHARACTER_NOT_NULL")) {
                                b = 74;
                            }
                            break;
                        case 1854890676:
                            if (errorMsg.equals("ERROR_BILL_NOT_NULL")) {
                                b = 53;
                            }
                            break;
                        case 1898328170:
                            if (errorMsg.equals("SYSTEM_ERROR_PAY_PASSWORD_ERROR_CODE")) {
                                b = 41;
                            }
                            break;
                        case 1936143911:
                            if (errorMsg.equals("INCORRECT_PHONE_NUMBER_FORMATG_CODE")) {
                                b = 35;
                            }
                            break;
                        case 1940543338:
                            if (errorMsg.equals("AUTHENTICATION_CANCELLATION")) {
                                b = 112;
                            }
                            break;
                        case 2000358825:
                            if (errorMsg.equals("ERROR_PAY_PASSWORD_NOT_NULL")) {
                                b = 44;
                            }
                            break;
                        case 2101432071:
                            if (errorMsg.equals("ERROR_TRANS_AMOUNT_MISMATCH")) {
                                b = 70;
                            }
                            break;
                        case 2129881790:
                            if (errorMsg.equals("SYSTEM_SMS_BUSY_COCE")) {
                                b = 30;
                            }
                            break;
                        case 2140948840:
                            if (errorMsg.equals("ERROR_OLD_PASSWORD_NOT_NULL")) {
                                b = 94;
                            }
                            break;
                    }
                    switch (b) {
                        case 0:
                            realErrorMsg = LocaleController.getString("OperationFailed", R.string.OperationFailed);
                            break;
                        case 1:
                            realErrorMsg = LocaleController.getString("IllegalOperation", R.string.IllegalOperation);
                            break;
                        case 2:
                            realErrorMsg = LocaleController.getString("OtherDeviceDoTheSame", R.string.OtherDeviceDoTheSame);
                            break;
                        case 3:
                            realErrorMsg = LocaleController.getString("ParameterError", R.string.ParameterError);
                            break;
                        case 4:
                            realErrorMsg = LocaleController.getString("CurrentUserNotOpenedWalletAccount", R.string.CurrentUserNotOpenedWalletAccount);
                            break;
                        case 5:
                            realErrorMsg = LocaleController.getString("OrderHasCompletedCanNotCancel", R.string.OrderHasCompletedCanNotCancel);
                            break;
                        case 6:
                            realErrorMsg = LocaleController.getString("OrderHasCanceledCanNotCancelRepetedly", R.string.OrderHasCanceledCanNotCancelRepetedly);
                            break;
                        case 7:
                            realErrorMsg = LocaleController.getString("OrderNotExist", R.string.OrderNotExist);
                            break;
                        case 8:
                            realErrorMsg = LocaleController.getString("OrderCanNotBeCancelled", R.string.OrderCanNotBeCancelled);
                            break;
                        case 9:
                            realErrorMsg = LocaleController.getString("AccountInformationMismatch", R.string.AccountInformationMismatch);
                            break;
                        case 10:
                            realErrorMsg = LocaleController.getString("RecipientInformationDoesNotExist", R.string.RecipientInformationDoesNotExist);
                            break;
                        case 11:
                        case 12:
                            realErrorMsg = LocaleController.getString("RefundIsNotSupportedForThisType", R.string.RefundIsNotSupportedForThisType);
                            break;
                        case 13:
                            realErrorMsg = LocaleController.getString("RedpacketYouHadReceievedCanNotReceivedRepetedly", R.string.RedpacketYouHadReceievedCanNotReceivedRepetedly);
                            break;
                        case 14:
                        case 15:
                            realErrorMsg = LocaleController.getString("RedpacketHadBeenCollected", R.string.RedpacketHadBeenCollected);
                            break;
                        case 16:
                            realErrorMsg = LocaleController.getString("RedpacketHadExpired", R.string.RedpacketHadExpired);
                            break;
                        case 17:
                            realErrorMsg = LocaleController.getString("RedpacketNotExist", R.string.RedpacketNotExist);
                            break;
                        case 18:
                            realErrorMsg = LocaleController.getString("RedpacketIsNotForYou", R.string.RedpacketIsNotForYou);
                            break;
                        case 19:
                            realErrorMsg = LocaleController.getString("RedpacketIsExclusivedIsNotForYou", R.string.RedpacketIsExclusivedIsNotForYou);
                            break;
                        case 20:
                            realErrorMsg = LocaleController.getString("RedpacketInfoMustNotNull", R.string.RedpacketInfoMustNotNull);
                            break;
                        case 21:
                            realErrorMsg = LocaleController.getString("TransferCompletedCannotReceivedRepetedly", R.string.TransferCompletedCannotReceivedRepetedly);
                            break;
                        case 22:
                            realErrorMsg = LocaleController.getString("TransferCompletedCannotCancelled", R.string.TransferCompletedCannotCancelled);
                            break;
                        case 23:
                            realErrorMsg = LocaleController.getString("YouAreNotMemberOfThisGroupYouCannotReceived", R.string.YouAreNotMemberOfThisGroupYouCannotReceived);
                            break;
                        case 24:
                            realErrorMsg = LocaleController.getString("TransferCancelledCannotCancelledRepetedly", R.string.TransferCancelledCannotCancelledRepetedly);
                            break;
                        case 25:
                            realErrorMsg = LocaleController.getString("OrderYouPaidCannotPayRepetedly", R.string.OrderYouPaidCannotPayRepetedly);
                            break;
                        case 26:
                            realErrorMsg = LocaleController.getString("TransferCannotBeReceived", R.string.TransferCannotBeReceived);
                            break;
                        case 27:
                            realErrorMsg = LocaleController.getString("AbnormalAccountInformation", R.string.AbnormalAccountInformation);
                            break;
                        case 28:
                            realErrorMsg = LocaleController.getString("PleaseSetPayPasswordFirst", R.string.PleaseSetPayPasswordFirst);
                            break;
                        case 29:
                            realErrorMsg = LocaleController.getString("CannotSendSMSRepeatedly", R.string.CannotSendSMSRepeatedly);
                            break;
                        case 30:
                            realErrorMsg = LocaleController.getString("SMSSystemIsBusy", R.string.SMSSystemIsBusy);
                            break;
                        case 31:
                            realErrorMsg = LocaleController.getString("VerificationcodeExpired", R.string.VerificationcodeExpired);
                            break;
                        case 32:
                            realErrorMsg = LocaleController.getString("VerificationcodeError", R.string.VerificationcodeError);
                            break;
                        case 33:
                            realErrorMsg = LocaleController.getString("NotSupportThisTypeFileToUpload", R.string.NotSupportThisTypeFileToUpload);
                            break;
                        case 34:
                            realErrorMsg = LocaleController.getString("NotSupportThisTypeBankCard", R.string.NotSupportThisTypeBankCard);
                            break;
                        case 35:
                            realErrorMsg = LocaleController.getString("IncorrectPhoneNumberFormat", R.string.IncorrectPhoneNumberFormat);
                            break;
                        case 36:
                            realErrorMsg = LocaleController.getString("TheAccountHasBeenFrozenWith24H", R.string.TheAccountHasBeenFrozenWith24H);
                            break;
                        case 37:
                            realErrorMsg = LocaleController.getString("TheAccountHasBeenFrozenWith24H", R.string.TheAccountHasBeenFrozenWith24H);
                            break;
                        case 38:
                            realErrorMsg = LocaleController.getString("TheAccountNotAuthedOrNotPassedPleaseAuthFirst", R.string.TheAccountNotAuthedOrNotPassedPleaseAuthFirst);
                            break;
                        case 39:
                            realErrorMsg = LocaleController.getString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater);
                            break;
                        case 40:
                            realErrorMsg = LocaleController.formatString("ErrorPayPasswordTimesYouAccountWillBeForzen", R.string.ErrorPayPasswordTimesYouAccountWillBeForzen, Integer.valueOf(WalletConfigBean.getInstance().getForzenTime()), Integer.valueOf(WalletConfigBean.getInstance().getForzenPayPasswordInputWrongTimes()));
                            break;
                        case 41:
                            realErrorMsg = LocaleController.formatString("ErrorPayPasswordTimesYouAccountWillLimitTrade", R.string.ErrorPayPasswordTimesYouAccountWillLimitTrade, Integer.valueOf(WalletConfigBean.getInstance().getTradePayPasswordInputWrongTimes()), Integer.valueOf(WalletConfigBean.getInstance().getTradeLimitTime()));
                            break;
                        case 42:
                            realErrorMsg = LocaleController.formatString("YourAccountHasBeenForzenTime", R.string.YourAccountHasBeenForzenTime, Integer.valueOf(WalletConfigBean.getInstance().getForzenTime()));
                            break;
                        case 43:
                            realErrorMsg = LocaleController.getString("UserNotNull", R.string.UserNotNull);
                            break;
                        case 44:
                            realErrorMsg = LocaleController.getString("PayPasswordNotNull", R.string.PayPasswordNotNull);
                            break;
                        case 45:
                            realErrorMsg = LocaleController.getString("ComfirmPayPasswordNotNull", R.string.ComfirmPayPasswordNotNull);
                            break;
                        case 46:
                            realErrorMsg = LocaleController.getString("NewPasswordInconsistent", R.string.NewPasswordInconsistent);
                            break;
                        case 47:
                            realErrorMsg = LocaleController.getString("VertificationCodeNotNull", R.string.VertificationCodeNotNull);
                            break;
                        case 48:
                            realErrorMsg = LocaleController.getString("UserNameNotNull", R.string.UserNameNotNull);
                            break;
                        case 49:
                            realErrorMsg = LocaleController.getString("IdCardNotNull", R.string.IdCardNotNull);
                            break;
                        case 50:
                            realErrorMsg = LocaleController.getString("TelNotNull", R.string.TelNotNull);
                            break;
                        case 51:
                            realErrorMsg = LocaleController.getString("TransferInfoNotNull", R.string.TransferInfoNotNull);
                            break;
                        case 52:
                            realErrorMsg = LocaleController.getString("RandomTimeNotNull", R.string.RandomTimeNotNull);
                            break;
                        case 53:
                            realErrorMsg = LocaleController.getString("BillInfoNotNull", R.string.BillInfoNotNull);
                            break;
                        case 54:
                            realErrorMsg = LocaleController.getString("RpkNumberIllegal", R.string.RpkNumberIllegal);
                            break;
                        case 55:
                            realErrorMsg = LocaleController.getString("ReceiverInfoNotNull", R.string.ReceiverInfoNotNull);
                            break;
                        case 56:
                            realErrorMsg = LocaleController.getString("GroupPersonRpkNumberError", R.string.GroupPersonRpkNumberError);
                            break;
                        case 57:
                            realErrorMsg = LocaleController.getString("ReceiverOrSellerNotNull", R.string.ReceiverOrSellerNotNull);
                            break;
                        case 58:
                            realErrorMsg = LocaleController.getString("RpkTypeNotNull", R.string.RpkTypeNotNull);
                            break;
                        case 59:
                            realErrorMsg = LocaleController.getString("GrantTypeNotNull", R.string.GrantTypeNotNull);
                            break;
                        case 60:
                            realErrorMsg = LocaleController.getString("NotAllowHairLuckRpk", R.string.NotAllowHairLuckRpk);
                            break;
                        case 61:
                            realErrorMsg = LocaleController.getString("RpkInfoError", R.string.RpkInfoError);
                            break;
                        case 62:
                            realErrorMsg = LocaleController.getString("FixedAmountNotNull", R.string.FixedAmountNotNull);
                            break;
                        case 63:
                            realErrorMsg = LocaleController.getString("InconsistentAmount", R.string.InconsistentAmount);
                            break;
                        case 64:
                            realErrorMsg = LocaleController.getString("AmountBelowMinLimit", R.string.AmountBelowMinLimit);
                            break;
                        case 65:
                            realErrorMsg = LocaleController.getString("RemarksNotNull", R.string.RemarksNotNull);
                            break;
                        case 66:
                            realErrorMsg = LocaleController.getString("MerchantOrderNumberNotNull", R.string.MerchantOrderNumberNotNull);
                            break;
                        case 67:
                            realErrorMsg = LocaleController.getString("UnitPriceNotNull", R.string.UnitPriceNotNull);
                            break;
                        case 68:
                            realErrorMsg = LocaleController.getString("ServiceChargeNotNull", R.string.ServiceChargeNotNull);
                            break;
                        case 69:
                            realErrorMsg = LocaleController.getString("TransactionAmountNotNull", R.string.TransactionAmountNotNull);
                            break;
                        case 70:
                            realErrorMsg = LocaleController.getString("TransAmountMismatch", R.string.TransAmountMismatch);
                            break;
                        case 71:
                            realErrorMsg = LocaleController.getString("TadditionalDataNotNull", R.string.TadditionalDataNotNull);
                            break;
                        case 72:
                            realErrorMsg = LocaleController.getString("DirectionOfBusinessNotNull", R.string.DirectionOfBusinessNotNull);
                            break;
                        case 73:
                            realErrorMsg = LocaleController.getString("TotalAmountOfCashSoldNotNull", R.string.TotalAmountOfCashSoldNotNull);
                            break;
                        case 74:
                            realErrorMsg = LocaleController.getString("RandomCharacterNotNull", R.string.RandomCharacterNotNull);
                            break;
                        case 75:
                            realErrorMsg = LocaleController.getString("ProductDescNotNull", R.string.ProductDescNotNull);
                            break;
                        case 76:
                            realErrorMsg = LocaleController.getString("TotalfeeNotNull", R.string.TotalfeeNotNull);
                            break;
                        case 77:
                            realErrorMsg = LocaleController.getString("InitiatorOrBuyerNotNull", R.string.InitiatorOrBuyerNotNull);
                            break;
                        case 78:
                            realErrorMsg = LocaleController.getString("TradeTypeNotNull", R.string.TradeTypeNotNull);
                            break;
                        case 79:
                            realErrorMsg = LocaleController.getString("NotSupportPay", R.string.NotSupportPay);
                            break;
                        case 80:
                            realErrorMsg = LocaleController.getString("ImgTypeNotNull", R.string.ImgTypeNotNull);
                            break;
                        case 81:
                            realErrorMsg = LocaleController.getString("AccountSynchronized", R.string.AccountSynchronized);
                            break;
                        case 82:
                            realErrorMsg = LocaleController.getString("SystemCodeAlready", R.string.SystemCodeAlready);
                            break;
                        case 83:
                            realErrorMsg = LocaleController.getString("TransferToExistSubmitRepeatedly", R.string.TransferToExistSubmitRepeatedly);
                            break;
                        case 84:
                            realErrorMsg = LocaleController.getString("RpkToExistSubmitRepeatedly", R.string.RpkToExistSubmitRepeatedly);
                            break;
                        case 85:
                            realErrorMsg = LocaleController.getString("OrderExistSubmitRepeatedly", R.string.OrderExistSubmitRepeatedly);
                            break;
                        case 86:
                            realErrorMsg = LocaleController.getString("OrderDoesNotExist", R.string.OrderDoesNotExist);
                            break;
                        case 87:
                            realErrorMsg = LocaleController.getString("OpenbankOrBankcodeNotNull", R.string.OpenbankOrBankcodeNotNull);
                            break;
                        case 88:
                            realErrorMsg = LocaleController.getString("GroupsNumberNotNull", R.string.GroupsNumberNotNull);
                            break;
                        case 89:
                            realErrorMsg = LocaleController.getString("PayChannelNotNull", R.string.PayChannelNotNull);
                            break;
                        case 90:
                            realErrorMsg = LocaleController.getString("NotSupportPayChannel", R.string.NotSupportPayChannel);
                            break;
                        case 91:
                            realErrorMsg = LocaleController.getString("AccountNotNull", R.string.AccountNotNull);
                            break;
                        case 92:
                            realErrorMsg = LocaleController.getString("AddressNotNull", R.string.AddressNotNull);
                            break;
                        case 93:
                            realErrorMsg = LocaleController.getString("BankInfoNotNull", R.string.BankInfoNotNull);
                            break;
                        case 94:
                            realErrorMsg = LocaleController.getString("OldPasswordNotNull", R.string.OldPasswordNotNull);
                            break;
                        case 95:
                            realErrorMsg = LocaleController.getString("OrderHasBeenComfirmed", R.string.OrderHasBeenComfirmed);
                            break;
                        case 96:
                            realErrorMsg = LocaleController.getString("AmountNotMatchComfireAmount", R.string.AmountNotMatchComfireAmount);
                            break;
                        case 97:
                            realErrorMsg = LocaleController.getString("CashAmountMismatch", R.string.CashAmountMismatch);
                            break;
                        case 98:
                            realErrorMsg = LocaleController.getString("BillInfoNotNull", R.string.BillInfoNotNull);
                            break;
                        case 99:
                            realErrorMsg = LocaleController.getString("NotSupport", R.string.NotSupport);
                            break;
                        case 100:
                            realErrorMsg = LocaleController.getString("TooManyRequest", R.string.TooManyRequest);
                            break;
                        case 101:
                            realErrorMsg = LocaleController.getString("TooManyRequest", R.string.TooManyRequest);
                            break;
                        case 102:
                            realErrorMsg = LocaleController.getString("AuthInfoMismatched", R.string.AuthInfoMismatched);
                            break;
                        case 103:
                            realErrorMsg = LocaleController.getString("AuthInfoInconsistent", R.string.AuthInfoInconsistent);
                            break;
                        case 104:
                            realErrorMsg = LocaleController.getString("PleaseBindBankCardFirst", R.string.PleaseBindBankCardFirst);
                            break;
                        case 105:
                            realErrorMsg = LocaleController.getString("BankCardInfoNotExists", R.string.BankCardInfoNotExists);
                            break;
                        case 106:
                            realErrorMsg = LocaleController.getString("TransferInfoNotExists", R.string.TransferInfoNotExists);
                            break;
                        case 107:
                            realErrorMsg = LocaleController.getString("TheBankCardHadBeenBound", R.string.TheBankCardHadBeenBound);
                            break;
                        case 108:
                            realErrorMsg = LocaleController.getString("CoinTypeCannotBeEmpty", R.string.CoinTypeCannotBeEmpty);
                            break;
                        case 109:
                            realErrorMsg = LocaleController.getString("TypeCannotBeEmpty", R.string.TypeCannotBeEmpty);
                            break;
                        case 110:
                            realErrorMsg = LocaleController.getString("NotSupportThisSMSType", R.string.NotSupportThisSMSType);
                            break;
                        case 111:
                            realErrorMsg = LocaleController.getString("PleaseVerifyYourPhoneCode", R.string.PleaseVerifyYourPhoneCode);
                            break;
                        case 112:
                            realErrorMsg = LocaleController.getString("RealNameAuthCancelSuccessTips", R.string.RealNameAuthCancelSuccessTips);
                            break;
                        case 113:
                            realErrorMsg = LocaleController.getString("ErrorVerifyPhoneCodeAndTryAgain", R.string.ErrorVerifyPhoneCodeAndTryAgain);
                            break;
                        case 114:
                            realErrorMsg = LocaleController.getString("BankCardInfoIsExists", R.string.BankCardInfoIsExists);
                            break;
                        case 115:
                            realErrorMsg = LocaleController.getString("CannotSupportThisBank", R.string.CannotSupportThisBank);
                            break;
                        case 116:
                            realErrorMsg = LocaleController.getString("NoPaymentChannelsAvailable", R.string.NoPaymentChannelsAvailable);
                            break;
                        case 117:
                            realErrorMsg = LocaleController.getString("BalanceIsNotEnough", R.string.BalanceIsNotEnough);
                            break;
                        case 118:
                            realErrorMsg = LocaleController.getString("RedpacketHadBeenWithdrawCannotBeClaimed", R.string.RedpacketHadBeenWithdrawCannotBeClaimed);
                            break;
                        case 119:
                            realErrorMsg = LocaleController.getString("TransferHadBeenCanceledCannotBeReceived", R.string.TransferHadBeenCanceledCannotBeReceived);
                            break;
                        case 120:
                            realErrorMsg = LocaleController.getString("AlreadyCollectedCantRepeat", R.string.AlreadyCollectedCantRepeat);
                            break;
                        case 121:
                            realErrorMsg = LocaleController.getString("IdCardNumberErrorTips", R.string.IdCardNumberErrorTips);
                            break;
                        case 122:
                            realErrorMsg = LocaleController.getString("BankCardNumberErrorTips", R.string.BankCardNumberErrorTips);
                            break;
                        case 123:
                            realErrorMsg = LocaleController.getString("NameErrorTips", R.string.NameErrorTips);
                            break;
                        case 124:
                            realErrorMsg = LocaleController.getString("DiffBankCardAndIdCardTips", R.string.DiffBankCardAndIdCardTips);
                            break;
                        case 125:
                            realErrorMsg = LocaleController.getString("NumberOfAddBankCardTodayHadExceededLimitTips", R.string.NumberOfAddBankCardTodayHadExceededLimitTips);
                            break;
                        case 126:
                            realErrorMsg = LocaleController.getString("SingleRedPacketAmoutExceedsUpperLimit", R.string.SingleRedPacketAmoutExceedsUpperLimit);
                            break;
                        case 127:
                            realErrorMsg = LocaleController.getString("SingleTransferAmoutExceedsUpperLimit", R.string.SingleTransferAmoutExceedsUpperLimit);
                            break;
                        case 128:
                            realErrorMsg = LocaleController.getString("BalanceIsNotEnough", R.string.BalanceIsNotEnough);
                            break;
                        case TsExtractor.TS_STREAM_TYPE_AC3 /* 129 */:
                            realErrorMsg = LocaleController.getString("AlreadyCdnVIP", R.string.AlreadyCdnVIP);
                            break;
                        default:
                            realErrorMsg = LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater);
                            break;
                    }
                }
            } else {
                String[] arr2 = NumberUtil.getNumbersFromStr(errorMsg);
                if (arr2.length == 2) {
                    realErrorMsg = LocaleController.formatString("ErrorPayPasswordTimesYouAccountWillBeForzen", R.string.ErrorPayPasswordTimesYouAccountWillBeForzen, arr2[0], arr2[1]);
                }
            }
            if (!TextUtils.isEmpty(prefixOfErrorMsg)) {
                return prefixOfErrorMsg + "  " + realErrorMsg;
            }
            return realErrorMsg;
        }
        return realErrorMsg;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x0186, code lost:
    
        if (r2.equals("40023") != false) goto L103;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x0192, code lost:
    
        if (r2.equals("50001") != false) goto L106;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x019e, code lost:
    
        if (r2.equals("45018") != false) goto L109;
     */
    /* JADX WARN: Code restructure failed: missing block: B:10:0x0019, code lost:
    
        switch(r0) {
            case 49560307: goto L47;
            case 49560308: goto L44;
            case 49560309: goto L41;
            default: goto L11;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x01aa, code lost:
    
        if (r2.equals("45017") != false) goto L112;
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x01b6, code lost:
    
        if (r2.equals("45016") != false) goto L115;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x01c2, code lost:
    
        if (r2.equals("45012") != false) goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x001c, code lost:
    
        switch(r0) {
            case 49590098: goto L38;
            case 49590099: goto L35;
            case 49590100: goto L32;
            case 49590101: goto L29;
            default: goto L12;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x01ce, code lost:
    
        if (r2.equals("45011") != false) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:123:0x01da, code lost:
    
        if (r2.equals("45010") != false) goto L124;
     */
    /* JADX WARN: Code restructure failed: missing block: B:126:0x01e6, code lost:
    
        if (r2.equals("45009") != false) goto L127;
     */
    /* JADX WARN: Code restructure failed: missing block: B:129:0x01f2, code lost:
    
        if (r2.equals("45008") != false) goto L130;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x001f, code lost:
    
        switch(r0) {
            case 49619889: goto L26;
            case 49619890: goto L23;
            case 49619891: goto L20;
            case 49619892: goto L17;
            case 49619893: goto L14;
            default: goto L224;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x01fe, code lost:
    
        if (r2.equals("45007") != false) goto L133;
     */
    /* JADX WARN: Code restructure failed: missing block: B:135:0x020a, code lost:
    
        if (r2.equals("45006") != false) goto L136;
     */
    /* JADX WARN: Code restructure failed: missing block: B:138:0x0216, code lost:
    
        if (r2.equals("45005") != false) goto L139;
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x0222, code lost:
    
        if (r2.equals("45004") != false) goto L142;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x022e, code lost:
    
        if (r2.equals("45003") != false) goto L145;
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x023a, code lost:
    
        if (r2.equals("45002") != false) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x0246, code lost:
    
        if (r2.equals("45001") != false) goto L151;
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x0252, code lost:
    
        if (r2.equals("41010") != false) goto L154;
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x025e, code lost:
    
        if (r2.equals("40066") != false) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x026a, code lost:
    
        if (r2.equals("40048") != false) goto L160;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x002a, code lost:
    
        if (r2.equals("44005") != false) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:162:0x0276, code lost:
    
        if (r2.equals("40039") != false) goto L163;
     */
    /* JADX WARN: Code restructure failed: missing block: B:165:0x0282, code lost:
    
        if (r2.equals("40030") != false) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x028e, code lost:
    
        if (r2.equals("40029") != false) goto L169;
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x029a, code lost:
    
        if (r2.equals("40020") != false) goto L172;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x02a6, code lost:
    
        if (r2.equals("40019") != false) goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:177:0x02b2, code lost:
    
        if (r2.equals("40018") != false) goto L178;
     */
    /* JADX WARN: Code restructure failed: missing block: B:180:0x02be, code lost:
    
        if (r2.equals("40017") != false) goto L181;
     */
    /* JADX WARN: Code restructure failed: missing block: B:183:0x02ca, code lost:
    
        if (r2.equals("40016") != false) goto L184;
     */
    /* JADX WARN: Code restructure failed: missing block: B:186:0x02d6, code lost:
    
        if (r2.equals("40015") != false) goto L187;
     */
    /* JADX WARN: Code restructure failed: missing block: B:189:0x02e2, code lost:
    
        if (r2.equals("40014") != false) goto L190;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0036, code lost:
    
        if (r2.equals("44004") != false) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:192:0x02ee, code lost:
    
        if (r2.equals("40013") != false) goto L193;
     */
    /* JADX WARN: Code restructure failed: missing block: B:195:0x02fa, code lost:
    
        if (r2.equals("40012") != false) goto L196;
     */
    /* JADX WARN: Code restructure failed: missing block: B:198:0x0305, code lost:
    
        if (r2.equals("40011") != false) goto L199;
     */
    /* JADX WARN: Code restructure failed: missing block: B:201:0x0310, code lost:
    
        if (r2.equals("40010") != false) goto L202;
     */
    /* JADX WARN: Code restructure failed: missing block: B:204:0x031a, code lost:
    
        if (r2.equals("40009") != false) goto L205;
     */
    /* JADX WARN: Code restructure failed: missing block: B:207:0x0324, code lost:
    
        if (r2.equals("40008") != false) goto L208;
     */
    /* JADX WARN: Code restructure failed: missing block: B:210:0x032e, code lost:
    
        if (r2.equals("40007") != false) goto L211;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0042, code lost:
    
        if (r2.equals("44003") != false) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x004e, code lost:
    
        if (r2.equals("44002") != false) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x005a, code lost:
    
        if (r2.equals("44001") != false) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0066, code lost:
    
        if (r2.equals("43004") != false) goto L31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0072, code lost:
    
        if (r2.equals("43003") != false) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x007e, code lost:
    
        if (r2.equals("43002") != false) goto L37;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x008a, code lost:
    
        if (r2.equals("43001") != false) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0096, code lost:
    
        if (r2.equals("42003") != false) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00a2, code lost:
    
        if (r2.equals("42002") != false) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00ae, code lost:
    
        if (r2.equals("42001") != false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:4:0x0007, code lost:
    
        switch(r0) {
            case 49500731: goto L209;
            case 49500732: goto L206;
            case 49500733: goto L203;
            default: goto L5;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00ba, code lost:
    
        if (r2.equals("41009") != false) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00c6, code lost:
    
        if (r2.equals("41008") != false) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x00d2, code lost:
    
        if (r2.equals("41007") != false) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:5:0x000a, code lost:
    
        switch(r0) {
            case 49500755: goto L200;
            case 49500756: goto L197;
            case 49500757: goto L194;
            case 49500758: goto L191;
            case 49500759: goto L188;
            case 49500760: goto L185;
            case 49500761: goto L182;
            case 49500762: goto L179;
            case 49500763: goto L176;
            case 49500764: goto L173;
            case 49500786: goto L170;
            case 49500795: goto L167;
            case 49500817: goto L164;
            case 49500826: goto L161;
            case 49500856: goto L158;
            case 49500916: goto L155;
            case 49530546: goto L152;
            case 49649680: goto L149;
            case 49649681: goto L146;
            case 49649682: goto L143;
            case 49649683: goto L140;
            case 49649684: goto L137;
            case 49649685: goto L134;
            case 49649686: goto L131;
            case 49649687: goto L128;
            case 49649688: goto L125;
            case 49649710: goto L122;
            case 49649711: goto L119;
            case 49649712: goto L116;
            case 49649716: goto L113;
            case 49649717: goto L110;
            case 49649718: goto L107;
            case 50424246: goto L104;
            default: goto L6;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x00de, code lost:
    
        if (r2.equals("41006") != false) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00ea, code lost:
    
        if (r2.equals("41005") != false) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x00f6, code lost:
    
        if (r2.equals("41004") != false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x0102, code lost:
    
        if (r2.equals("41003") != false) goto L70;
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x000d, code lost:
    
        switch(r0) {
            case 49500789: goto L101;
            case 49500790: goto L98;
            case 49500791: goto L95;
            case 49500792: goto L92;
            case 49500793: goto L89;
            default: goto L7;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x010e, code lost:
    
        if (r2.equals("41002") != false) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x011a, code lost:
    
        if (r2.equals("41001") != false) goto L76;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0126, code lost:
    
        if (r2.equals("40055") != false) goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:7:0x0010, code lost:
    
        switch(r0) {
            case 49500823: goto L86;
            case 49500824: goto L83;
            default: goto L8;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x0132, code lost:
    
        if (r2.equals("40054") != false) goto L82;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x013e, code lost:
    
        if (r2.equals("40037") != false) goto L85;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x014a, code lost:
    
        if (r2.equals("40036") != false) goto L88;
     */
    /* JADX WARN: Code restructure failed: missing block: B:8:0x0013, code lost:
    
        switch(r0) {
            case 49500883: goto L80;
            case 49500884: goto L77;
            default: goto L9;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x0156, code lost:
    
        if (r2.equals("40027") != false) goto L91;
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x0162, code lost:
    
        if (r2.equals("40026") != false) goto L94;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x016e, code lost:
    
        if (r2.equals("40025") != false) goto L97;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x017a, code lost:
    
        if (r2.equals("40024") != false) goto L100;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x0016, code lost:
    
        switch(r0) {
            case 49530516: goto L74;
            case 49530517: goto L71;
            case 49530518: goto L68;
            case 49530519: goto L65;
            case 49530520: goto L62;
            case 49530521: goto L59;
            case 49530522: goto L56;
            case 49530523: goto L53;
            case 49530524: goto L50;
            default: goto L10;
        };
     */
    /* JADX WARN: Removed duplicated region for block: B:224:0x035a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String getWeChatPayErrorDescription(java.lang.String r2) {
        /*
            Method dump skipped, instruction units count: 1462
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil.getWeChatPayErrorDescription(java.lang.String):java.lang.String");
    }
}
