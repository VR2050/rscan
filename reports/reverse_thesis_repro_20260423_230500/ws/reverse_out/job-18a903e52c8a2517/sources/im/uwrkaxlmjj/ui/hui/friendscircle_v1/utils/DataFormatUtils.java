package im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils;

import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.RespFcListBean;
import im.uwrkaxlmjj.javaBean.fc.AllMsgBean;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class DataFormatUtils {
    /* JADX WARN: Multi-variable type inference failed */
    public static ArrayList<FcReplyBean> formatFcReplylListBean(ArrayList<FcReplyBean> arrayList) {
        ArrayList<FcReplyBean> arrayList2 = new ArrayList<>();
        ArrayList arrayList3 = new ArrayList();
        for (int i = 0; i < arrayList.size(); i++) {
            if (arrayList.get(i).getSupID() == 0) {
                arrayList2.add(arrayList.get(i));
            } else {
                arrayList3.add(arrayList.get(i));
            }
        }
        for (int i2 = 0; i2 < arrayList2.size(); i2++) {
            long parentReplyId = arrayList2.get(i2).getCommentID();
            ArrayList arrayList4 = new ArrayList();
            for (int j = 0; j < arrayList3.size(); j++) {
                if (parentReplyId == ((FcReplyBean) arrayList3.get(j)).getSupID()) {
                    arrayList4.add(arrayList3.get(j));
                }
            }
            arrayList2.get(i2).setSubComment(arrayList4);
        }
        arrayList.clear();
        arrayList.addAll(arrayList2);
        return arrayList2;
    }

    public static ArrayList<AllMsgBean> formatFcUnredReplyLike(ArrayList<FcReplyBean> replyList) {
        ArrayList<AllMsgBean> alllist = new ArrayList<>();
        for (FcReplyBean fcReplyBean : replyList) {
        }
        return alllist;
    }

    public static void formatResponseFclistBean4DB(ArrayList<RespFcListBean> mRespFcListBeanList) {
        for (RespFcListBean temp : mRespFcListBeanList) {
            temp.setForumID(temp.getForumID());
        }
    }

    public static String getUserNameByid(BaseFragment mBaseFragment, long userId) {
        TLRPC.User itemUser = mBaseFragment.getAccountInstance().getMessagesController().getUser(Integer.valueOf((int) userId));
        if (itemUser != null) {
            return StringUtils.handleTextName(ContactsController.formatName(itemUser.first_name, itemUser.last_name), 12);
        }
        return userId + "";
    }

    public static String getUserNameByid(BaseFmts mBaseFragment, long userId) {
        TLRPC.User itemUser = mBaseFragment.getAccountInstance().getMessagesController().getUser(Integer.valueOf((int) userId));
        if (itemUser != null) {
            return StringUtils.handleTextName(ContactsController.formatName(itemUser.first_name, itemUser.last_name), 12);
        }
        return userId + "";
    }

    public static String getUserNameByid(long userId) {
        TLRPC.User itemUser = MessagesController.getInstance(UserConfig.selectedAccount).getUser(Integer.valueOf((int) userId));
        if (itemUser != null) {
            return StringUtils.handleTextName(ContactsController.formatName(itemUser.first_name, itemUser.last_name), 12);
        }
        return userId + "";
    }
}
