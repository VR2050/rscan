package com.bjz.comm.net.mvp.model;

import com.android.tools.r8.annotations.SynthesizedClassMap;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.BResponseNoData;
import com.bjz.comm.net.bean.FcBgBean;
import com.bjz.comm.net.bean.FcIgnoreUserBean;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.RequestReplyFcBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.utils.JsonCreateUtils;
import com.bjz.comm.net.utils.RxHelper;
import io.reactivex.Observable;
import java.util.ArrayList;
import okhttp3.RequestBody;

/* JADX INFO: loaded from: classes4.dex */
@SynthesizedClassMap({$$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI.class, $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo.class, $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s.class})
public class FcCommItemModel implements BaseFcContract.IFcCommItemModel {
    private static final String TAG = FcCommItemModel.class.getSimpleName();

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void getFcBackgroundUrl(long userId, DataListener<BResponse<FcBgBean>> listener) {
        Observable<BResponse<FcBgBean>> observable = ApiFactory.getInstance().getApiMomentForum().getFCBackground(userId);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doFollow(long followUID, DataListener<BResponseNoData> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("FollowUID", Long.valueOf(followUID)).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().doFollow(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo __lambda_q4eitxgqnlbs9f1srtgjxo_xkco = new $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo(listener);
        listener.getClass();
        rxHelper.sendRequestNoData(str, observable, __lambda_q4eitxgqnlbs9f1srtgjxo_xkco, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doCancelFollowed(long followUID, DataListener<BResponseNoData> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("FollowUID", Long.valueOf(followUID)).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().doCancelFollowed(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo __lambda_q4eitxgqnlbs9f1srtgjxo_xkco = new $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo(listener);
        listener.getClass();
        rxHelper.sendRequestNoData(str, observable, __lambda_q4eitxgqnlbs9f1srtgjxo_xkco, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doLike(long forumID, long forumUID, long commentID, long commentUID, DataListener<BResponse<FcLikeBean>> listener) {
        JsonCreateUtils.MapForJsonObject build = JsonCreateUtils.build();
        build.addParam("ForumID", Long.valueOf(forumID)).addParam("UpDown", 1);
        if (commentID != -1 && commentUID != -1) {
            build.addParam("CommentID", Long.valueOf(commentID));
        }
        RequestBody requestBody = build.getHttpBody();
        Observable<BResponse<FcLikeBean>> observable = ApiFactory.getInstance().getApiMomentForum().doLike(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doCancelLike(long forumID, long forumUID, long commentID, long commentUID, DataListener<BResponse<FcLikeBean>> listener) {
        JsonCreateUtils.MapForJsonObject build = JsonCreateUtils.build();
        build.addParam("ForumID", Long.valueOf(forumID));
        build.addParam("ForumUID", Long.valueOf(forumUID));
        if (commentID != -1 && commentUID != -1) {
            build.addParam("CommentID", Long.valueOf(commentID));
            build.addParam("CommentUID", Long.valueOf(commentUID));
        }
        RequestBody requestBody = build.getHttpBody();
        Observable<BResponse<FcLikeBean>> observable = ApiFactory.getInstance().getApiMomentForum().doCancelLike(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doDeleteItem(long forumID, DataListener<BResponseNoData> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("ForumID", Long.valueOf(forumID)).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().doDeleteItem(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo __lambda_q4eitxgqnlbs9f1srtgjxo_xkco = new $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo(listener);
        listener.getClass();
        rxHelper.sendRequestNoData(str, observable, __lambda_q4eitxgqnlbs9f1srtgjxo_xkco, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doIgnoreItem(long forumID, DataListener<BResponseNoData> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("ForumID", Long.valueOf(forumID)).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().doIgnoreItem(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo __lambda_q4eitxgqnlbs9f1srtgjxo_xkco = new $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo(listener);
        listener.getClass();
        rxHelper.sendRequestNoData(str, observable, __lambda_q4eitxgqnlbs9f1srtgjxo_xkco, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doSetItemPermission(long forumID, int permission, DataListener<BResponseNoData> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("ForumID", Long.valueOf(forumID)).addParam("Permission", Integer.valueOf(permission)).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().doSetItemPermission(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo __lambda_q4eitxgqnlbs9f1srtgjxo_xkco = new $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo(listener);
        listener.getClass();
        rxHelper.sendRequestNoData(str, observable, __lambda_q4eitxgqnlbs9f1srtgjxo_xkco, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doAddIgnoreUser(ArrayList<FcIgnoreUserBean> ignores, DataListener<BResponse<ArrayList<FcIgnoreUserBean>>> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("Ignores", ignores).getHttpBody();
        Observable<BResponse<ArrayList<FcIgnoreUserBean>>> observable = ApiFactory.getInstance().getApiMomentForum().doAddIgnoreUser(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendCommRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doDeleteIgnoreUser(ArrayList<FcIgnoreUserBean> ignores, DataListener<BResponse<ArrayList<FcIgnoreUserBean>>> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("Ignores", ignores).getHttpBody();
        Observable<BResponse<ArrayList<FcIgnoreUserBean>>> observable = ApiFactory.getInstance().getApiMomentForum().doDeleteIgnoreUser(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendCommRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doReply(RequestReplyFcBean bean, DataListener<BResponse<FcReplyBean>> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("ForumID", Long.valueOf(bean.getForumID())).addParam("ForumUser", Long.valueOf(bean.getForumUser())).addParam("SupID", Long.valueOf(bean.getSupID())).addParam("SupUser", Long.valueOf(bean.getSupUser())).addParam("ReplayID", Long.valueOf(bean.getReplayID())).addParam("ReplayUID", Long.valueOf(bean.getReplayUID())).addParam("Content", bean.getContent()).addParam("Entitys", bean.getEntitys()).getHttpBody();
        Observable<BResponse<FcReplyBean>> observable = ApiFactory.getInstance().getApiMomentForum().replyForum(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemModel
    public void doDeleteComment(long commentID, long forumID, long forumUser, DataListener<BResponseNoData> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("CommentID", Long.valueOf(commentID)).addParam("ForumID", Long.valueOf(forumID)).addParam("ForumUser", Long.valueOf(forumUser)).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().deleteReplyForum(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo __lambda_q4eitxgqnlbs9f1srtgjxo_xkco = new $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo(listener);
        listener.getClass();
        rxHelper.sendRequestNoData(str, observable, __lambda_q4eitxgqnlbs9f1srtgjxo_xkco, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.base.IBModel
    public void unSubscribeTask() {
        RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(TAG);
    }
}
