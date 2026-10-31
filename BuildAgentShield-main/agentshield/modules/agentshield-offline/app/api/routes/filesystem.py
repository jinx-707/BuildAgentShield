"""
AgentShield Offline — Local Filesystem API Routes.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_runtime, verify_api_key
from app.core.contracts import (
    BaseOfflineResponse,
    FileCopyRequest,
    FileCreateRequest,
    FileDeleteRequest,
    FileListRequest,
    FileMoveRequest,
    FileReadRequest,
    FileSearchRequest,
    FileUpdateRequest,
)
from app.core.runtime import OfflineSecurityRuntime

router = APIRouter(prefix="/files", tags=["Local File Access"])


@router.post("/read", response_model=BaseOfflineResponse, summary="Read a file")
async def read_file(
    request: FileReadRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.read_file(request)


@router.post("/search", response_model=BaseOfflineResponse, summary="Search files")
async def search_files(
    request: FileSearchRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.search_files(request)


@router.post("/list", response_model=BaseOfflineResponse, summary="List a directory")
async def list_directory(
    request: FileListRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.list_directory(request)


@router.post("/create", response_model=BaseOfflineResponse, summary="Create a file")
async def create_file(
    request: FileCreateRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.create_file(request)


@router.post("/update", response_model=BaseOfflineResponse, summary="Update a file")
async def update_file(
    request: FileUpdateRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.update_file(request)


@router.post("/delete", response_model=BaseOfflineResponse, summary="Delete a file")
async def delete_file(
    request: FileDeleteRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.delete_file(request)


@router.post("/move", response_model=BaseOfflineResponse, summary="Move a file")
async def move_file(
    request: FileMoveRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.move_file(request)


@router.post("/copy", response_model=BaseOfflineResponse, summary="Copy a file")
async def copy_file(
    request: FileCopyRequest,
    _key: Annotated[str, Depends(verify_api_key)],
    runtime: Annotated[OfflineSecurityRuntime, Depends(get_runtime)],
) -> BaseOfflineResponse:
    return await runtime.copy_file(request)
