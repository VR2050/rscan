package com.bjz.comm.net.mvp.model;

import com.android.tools.r8.annotations.SynthesizedClassMap;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.RespFcLikesBean;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.RespFcReplyBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.utils.RxHelper;
import io.reactivex.Observable;

/* JADX INFO: loaded from: classes4.dex */
@SynthesizedClassMap({$$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI.class, $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s.class})
public class FcPageDetailModel implements BaseFcContract.IFcPageDetailModel {
    private static final String TAG = FcPageDetailModel.class.getSimpleName();

    @Override // com.bjz.comm.net.base.IBModel
    public void unSubscribeTask() {
        RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(TAG);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailModel
    public void getDetail(long forumID, long forumUserId, DataListener<BResponse<RespFcListBean>> listener) {
        Observable<BResponse<RespFcListBean>> observable = ApiFactory.getInstance().getApiMomentForum().getDetail(forumID, forumUserId);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailModel
    public void getComments(long forumID, long commentId, long forumUserId, int limit, DataListener<BResponse<RespFcReplyBean>> listener) {
        Observable<BResponse<RespFcReplyBean>> observable = ApiFactory.getInstance().getApiMomentForum().getComments(forumID, commentId, forumUserId, limit, 2);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailModel
    public void getReplyList(FcReplyBean parentFcReplyBean, long commentId, int limit, DataListener<BResponse<RespFcReplyBean>> listener) {
        Observable<BResponse<RespFcReplyBean>> observable = ApiFactory.getInstance().getApiMomentForum().getReplyList(parentFcReplyBean.getForumID(), commentId, parentFcReplyBean.getCommentID(), parentFcReplyBean.getCreateBy(), limit);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageDetailModel
    public void getLikeUserList(long forumId, long thumbId, int limit, DataListener<BResponse<RespFcLikesBean>> listener) {
        Observable<BResponse<RespFcLikesBean>> observable = ApiFactory.getInstance().getApiMomentForum().getLikeUserList(forumId, thumbId, 1L, limit);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }
}
