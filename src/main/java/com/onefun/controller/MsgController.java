package com.onefun.controller;

import org.springframework.web.bind.annotation.*;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;

import com.onefun.service.MsgService;
import com.onefun.util.JSONResult;
import com.onefun.entity.Msg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.swagger.annotations.*;
/**
 *code is far away from bug with the animal protecting
 *　　
 *   @description : Msg 控制器
 *   ---------------------------------
 * 	 @author Lin_huanwen123
 *   @since 2018-07-26
 */
@RestController
@Api(value="/msg", description="Msg 控制器")
@RequestMapping("/msg")
public class MsgController {
    private final Logger logger = LoggerFactory.getLogger(MsgController.class);

    @Autowired
    public MsgService msgService;

    /**
     * @description : 通过id获取Msg
     * ---------------------------------
     * @author : Lin_huanwen123
     * @since : Create in 2018-07-26
     */
    @GetMapping("/getMsgById")
    @ApiOperation(value="通过id获取Msg", notes="通过id获取Msg")
    @ApiImplicitParam(name = "id", paramType="query", value = "MsgID", dataType="integer", required = true)
    public JSONResult<Msg> getMsgById(Integer id) throws Exception{
            JSONResult<Msg> resJson = new JSONResult<>();
            Msg param= msgService.selectOneByObj(id);
            resJson.setData(param);
            resJson.setStatus(0);
            return resJson;
    }

    /**
     * @description : 通过id删除Msg
     * ---------------------------------
     * @author : Lin_huanwen123
     * @since : Create in 2018-07-26
     */
    @GetMapping("/deleteMsgById")
    @ApiOperation(value="通过id删除Msg", notes="通过id删除Msg")
    @ApiImplicitParam(name = "id", paramType="query", value = "MsgID", dataType="integer", required = true)
    public JSONResult<Msg> deleteMsgById(Integer id) throws Exception{
            JSONResult<Msg> resJson = new JSONResult<>();
            boolean boo=msgService.deleteById(id);
            resJson.setStatus(boo?0:1);
            return resJson;
    }

    /**
     * @description : 通过id更新Msg
     * ---------------------------------
     * @author : Lin_huanwen123
     * @since : Create in 2018-07-26
     */
    @PostMapping("/updateMsgById")
    @ApiOperation(value="通过id更新Msg", notes="通过id更新Msg")
    public JSONResult<Msg> updateMsgById(@ApiParam(name="Msg",value="Msg 实体类") @RequestBody Msg param) throws Exception{
            JSONResult<Msg> resJson = new JSONResult<>();
            boolean boo=msgService.updateById(param);
            resJson.setStatus(boo?0:1);
            return resJson;
    }

    /**
     * @description : 添加Msg
     * ---------------------------------
     * @author : Lin_huanwen123
     * @since : Create in 2018-07-26
     */
	@PostMapping("/addMsg")
    @ApiOperation(value="添加Msg", notes="添加Msg")
    public JSONResult<Msg> addMsg(@ApiParam(name="Msg",value="Msg 实体类") @RequestBody Msg param) throws Exception{
            JSONResult<Msg> resJson = new JSONResult<>();
            boolean boo=msgService.insert(param);
            resJson.setStatus(boo?0:1);
            return resJson;
    }
}
