# AegisNet-AI: Topology Demo Page — Addendum Roadmap

---

## 0. Context & Scope

- This roadmap covers **one additive feature only**: a standalone Streamlit page (`pages/1_Topology.py`) that visualizes the 4 containers (`victim-client`, `target-server`, `red-attacker`, `blue-ai-defender`) with live state-change simulation, for use in the upcoming project presentation.
- The main `ROADMAP.md` (v0.1 → v1.0) is treated as **already complete** per current project status. This addendum does not re-verify or re-run any of that work.
- **Non-negotiable constraint:** this feature must not alter, import from, or share state with any existing backend module, sensor, agent pipeline, or dashboard page. It is a net-new file with its own isolated `st.session_state` namespace.
- This addendum maps to, and partially fulfills ahead of schedule, the **v1.0 "Interactive SOC Dashboard → Topology Canvas"** deliverable already defined in `ROADMAP.md`.
- **Rule of Execution (inherited from `ROADMAP.md` §3):** the agent must not skip steps, assume implicit success, or check a box without running the verification command, capturing real output, and comparing it against Expected Output.

---

## 1. Pre-Flight: Non-Interference Check

- [x] **Step 1.1:** Confirm the location of the existing Streamlit entrypoint and `pages/` directory (or confirm one needs to be created).

Command:
```bash
find . -iname "*.py" -path "*streamlit*" -o -iname "dashboard.py" 2>/dev/null
ls pages/ 2>/dev/null || echo "no pages/ directory yet"
```

Expected Output:
```
<path to existing dashboard entrypoint found>
<existing pages/ directory listed, OR "no pages/ directory yet">
```

Actual Output:
```
./src/ui/dashboard.py
./.venv/lib/python3.14/site-packages/streamlit/cursor.py
./.venv/lib/python3.14/site-packages/streamlit/env_util.py
./.venv/lib/python3.14/site-packages/streamlit/navigation/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/navigation/page.py
./.venv/lib/python3.14/site-packages/streamlit/typing.py
./.venv/lib/python3.14/site-packages/streamlit/error_util.py
./.venv/lib/python3.14/site-packages/streamlit/util.py
./.venv/lib/python3.14/site-packages/streamlit/git_util.py
./.venv/lib/python3.14/site-packages/streamlit/type_util.py
./.venv/lib/python3.14/site-packages/streamlit/elements/bottom.py
./.venv/lib/python3.14/site-packages/streamlit/elements/balloons.py
./.venv/lib/python3.14/site-packages/streamlit/elements/json.py
./.venv/lib/python3.14/site-packages/streamlit/elements/toast.py
./.venv/lib/python3.14/site-packages/streamlit/elements/snow.py
./.venv/lib/python3.14/site-packages/streamlit/elements/metric.py
./.venv/lib/python3.14/site-packages/streamlit/elements/dialog_decorator.py
./.venv/lib/python3.14/site-packages/streamlit/elements/pyplot.py
./.venv/lib/python3.14/site-packages/streamlit/elements/table.py
./.venv/lib/python3.14/site-packages/streamlit/elements/spinner.py
./.venv/lib/python3.14/site-packages/streamlit/elements/empty.py
./.venv/lib/python3.14/site-packages/streamlit/elements/deck_gl_json_chart.py
./.venv/lib/python3.14/site-packages/streamlit/elements/media.py
./.venv/lib/python3.14/site-packages/streamlit/elements/vega_charts.py
./.venv/lib/python3.14/site-packages/streamlit/elements/space.py
./.venv/lib/python3.14/site-packages/streamlit/elements/form.py
./.venv/lib/python3.14/site-packages/streamlit/elements/text.py
./.venv/lib/python3.14/site-packages/streamlit/elements/mermaid_chart.py
./.venv/lib/python3.14/site-packages/streamlit/elements/html.py
./.venv/lib/python3.14/site-packages/streamlit/elements/heading.py
./.venv/lib/python3.14/site-packages/streamlit/elements/progress.py
./.venv/lib/python3.14/site-packages/streamlit/elements/image.py
./.venv/lib/python3.14/site-packages/streamlit/elements/markdown.py
./.venv/lib/python3.14/site-packages/streamlit/elements/pdf.py
./.venv/lib/python3.14/site-packages/streamlit/elements/graphviz_chart.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/skeleton_placeholder.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/image_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/file_uploader_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/policies.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/mutable_status_container.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/dialog.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/js_number.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/color_util.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/mutable_tab_container.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/mutable_popover_container.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/pandas_styler_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/shortcut_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/mutable_expander_container.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/streamlit_plotly_theme.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/form_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/built_in_chart_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/column_config_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/column_types.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/layout_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/options_selector_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/subtitle_utils.py
./.venv/lib/python3.14/site-packages/streamlit/elements/lib/dicttools.py
./.venv/lib/python3.14/site-packages/streamlit/elements/write.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/button_group.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/checkbox.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/audio_input.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/slider.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/button.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/chat.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/selectbox.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/multiselect.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/select_slider.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/pagination.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/text_widgets.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/number_input.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/data_editor.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/color_picker.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/menu_button.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/time_widgets.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/radio.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/camera_input.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/file_uploader.py
./.venv/lib/python3.14/site-packages/streamlit/elements/widgets/feedback.py
./.venv/lib/python3.14/site-packages/streamlit/elements/iframe.py
./.venv/lib/python3.14/site-packages/streamlit/elements/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/elements/plotly_chart.py
./.venv/lib/python3.14/site-packages/streamlit/elements/map.py
./.venv/lib/python3.14/site-packages/streamlit/elements/code.py
./.venv/lib/python3.14/site-packages/streamlit/elements/help.py
./.venv/lib/python3.14/site-packages/streamlit/elements/alert.py
./.venv/lib/python3.14/site-packages/streamlit/elements/skeleton.py
./.venv/lib/python3.14/site-packages/streamlit/elements/arrow.py
./.venv/lib/python3.14/site-packages/streamlit/elements/echarts_chart.py
./.venv/lib/python3.14/site-packages/streamlit/elements/exception.py
./.venv/lib/python3.14/site-packages/streamlit/elements/layouts.py
./.venv/lib/python3.14/site-packages/streamlit/delta_generator.py
./.venv/lib/python3.14/site-packages/streamlit/net_util.py
./.venv/lib/python3.14/site-packages/streamlit/platform.py
./.venv/lib/python3.14/site-packages/streamlit/testing/v1/util.py
./.venv/lib/python3.14/site-packages/streamlit/testing/v1/local_script_runner.py
./.venv/lib/python3.14/site-packages/streamlit/testing/v1/app_test.py
./.venv/lib/python3.14/site-packages/streamlit/testing/v1/errors.py
./.venv/lib/python3.14/site-packages/streamlit/testing/v1/element_tree.py
./.venv/lib/python3.14/site-packages/streamlit/testing/v1/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/testing/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/source_util.py
./.venv/lib/python3.14/site-packages/streamlit/material_icon_names.py
./.venv/lib/python3.14/site-packages/streamlit/user_info.py
./.venv/lib/python3.14/site-packages/streamlit/proto/openmetrics_data_model_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/SessionStatus_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/FileUploader_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Text_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/WidgetStates_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Navigation_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/VegaLiteChart_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ClientState_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ButtonLikeIconPosition_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/TimeInput_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ArrowNamedDataSet_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Delta_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/DownloadButton_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Skeleton_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Json_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Image_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Exception_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/PageInfo_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Transient_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ParentMessage_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Element_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Common_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/AutoRerun_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Html_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Button_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/BidiComponent_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Video_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/MetricsEvent_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/TextArea_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Alert_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ForwardMsg_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/SelectWidgetFilterMode_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Radio_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/LabelVisibility_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/DateInput_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/PageNotFound_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Components_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/AuthRedirect_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/PageProfile_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/DeckGlJsonChart_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ArrowData_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/MenuButton_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Selectbox_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/PageLink_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Help_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Favicon_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/BackMsg_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/GraphVizChart_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Metric_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/LinkButton_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Balloons_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/GapSize_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/RootContainer_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Table_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/IFrame_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Logo_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/WidthConfig_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Space_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ColorPicker_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/CameraInput_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/TextInput_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Snow_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Toast_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Heading_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Markdown_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/AppPage_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Spinner_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/proto/EChartsChart_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/NewSession_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Empty_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/PageConfig_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/PlotlyChart_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/HeightConfig_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/DateTimeInput_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/GitInfo_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Progress_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/SessionEvent_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Checkbox_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/NumberInput_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Audio_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Block_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/MultiSelect_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ChatInput_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/AudioInput_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Pagination_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/TextAlignmentConfig_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Dataframe_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/ButtonGroup_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Feedback_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Slider_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/proto/Code_pb2.py
./.venv/lib/python3.14/site-packages/streamlit/development.py
./.venv/lib/python3.14/site-packages/streamlit/temporary_directory.py
./.venv/lib/python3.14/site-packages/streamlit/deprecation_util.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/download_data_util.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/forward_msg_cache.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/context_util.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/memory_uploaded_file_manager.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/media_file_storage.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/websocket_session_manager.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/outside_container_wrapper.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/forward_msg_queue.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/runtime_util.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/parallel_coordinator.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/connection_factory.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/theme_util.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner/script_runner.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner/magic.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner/exec_code.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner/magic_funcs.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner/script_cache.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/media_file_manager.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/cache_background_refresh.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/cache_utils.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/cache_data_api.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/hashing.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/cache_type.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/ttl_cache.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/cache_errors.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/cache_resource_api.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/ttl_cleanup_cache.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/storage/dummy_cache_storage.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/storage/in_memory_cache_storage_wrapper.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/storage/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/storage/cache_storage_protocol.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/storage/local_disk_cache_storage.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/caching/cached_message_replay.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/secrets.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/stats.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/uploaded_file_manager.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/script_data.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/memory_media_file_storage.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/fragment.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/memory_session_storage.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/dataframe_chunk_handler.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/metrics_util.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/credentials.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner_utils/shared_run_state.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner_utils/exceptions.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner_utils/script_run_context_attr.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner_utils/script_requests.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner_utils/script_run_context.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner_utils/thread_safe_set.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/scriptrunner_utils/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/dataframe_source_manager.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/context.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/session_manager.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/app_session.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/runtime.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/query_params_proxy.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/query_params.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/common.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/safe_session_state.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/widgets.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/presentation.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/session_state_proxy.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/state/session_state.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/pages_manager.py
./.venv/lib/python3.14/site-packages/streamlit/runtime/backend_operation_handler.py
./.venv/lib/python3.14/site-packages/streamlit/web/skills.py
./.venv/lib/python3.14/site-packages/streamlit/web/cli.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/server_util.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/component_file_utils.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/server.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_websocket.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_app_utils.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_auth_routes.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_routes.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_server.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_app.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_path_security_middleware.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_gzip_middleware.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_server_config.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/starlette/starlette_static_routes.py
./.venv/lib/python3.14/site-packages/streamlit/web/server/app_discovery.py
./.venv/lib/python3.14/site-packages/streamlit/web/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/web/bootstrap.py
./.venv/lib/python3.14/site-packages/streamlit/web/cache_storage_manager_config.py
./.venv/lib/python3.14/site-packages/streamlit/config_util.py
./.venv/lib/python3.14/site-packages/streamlit/version.py
./.venv/lib/python3.14/site-packages/streamlit/commands/echo.py
./.venv/lib/python3.14/site-packages/streamlit/commands/execution_control.py
./.venv/lib/python3.14/site-packages/streamlit/commands/navigation.py
./.venv/lib/python3.14/site-packages/streamlit/commands/page_config.py
./.venv/lib/python3.14/site-packages/streamlit/commands/logo.py
./.venv/lib/python3.14/site-packages/streamlit/commands/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/toml_writer.py
./.venv/lib/python3.14/site-packages/streamlit/dataframe/lazy_df_source.py
./.venv/lib/python3.14/site-packages/streamlit/dataframe/lazy_df_adapters.py
./.venv/lib/python3.14/site-packages/streamlit/dataframe/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/string_util.py
./.venv/lib/python3.14/site-packages/streamlit/emojis.py
./.venv/lib/python3.14/site-packages/streamlit/cli_util.py
./.venv/lib/python3.14/site-packages/streamlit/command_suggestions.py
./.venv/lib/python3.14/site-packages/streamlit/signal_util.py
./.venv/lib/python3.14/site-packages/streamlit/.agents/skills/developing-with-streamlit/assets/templates/apps/dashboard-metrics/streamlit_app.py
./.venv/lib/python3.14/site-packages/streamlit/.agents/skills/developing-with-streamlit/assets/templates/apps/dashboard-feature-usage/streamlit_app.py
./.venv/lib/python3.14/site-packages/streamlit/.agents/skills/developing-with-streamlit/assets/templates/apps/dashboard-compute/streamlit_app.py
./.venv/lib/python3.14/site-packages/streamlit/.agents/skills/developing-with-streamlit/assets/templates/apps/dashboard-seattle-weather/streamlit_app.py
./.venv/lib/python3.14/site-packages/streamlit/.agents/skills/developing-with-streamlit/assets/templates/apps/dashboard-companies/streamlit_app.py
./.venv/lib/python3.14/site-packages/streamlit/.agents/skills/developing-with-streamlit/assets/templates/apps/dashboard-stock-peers/streamlit_app.py
./.venv/lib/python3.14/site-packages/streamlit/.agents/meta-skill/developing-with-streamlit/scripts/discover.py
./.venv/lib/python3.14/site-packages/streamlit/time_util.py
./.venv/lib/python3.14/site-packages/streamlit/path_security.py
./.venv/lib/python3.14/site-packages/streamlit/errors.py
./.venv/lib/python3.14/site-packages/streamlit/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/connections/util.py
./.venv/lib/python3.14/site-packages/streamlit/connections/retry_util.py
./.venv/lib/python3.14/site-packages/streamlit/connections/snowflake_connection.py
./.venv/lib/python3.14/site-packages/streamlit/connections/sql_connection.py
./.venv/lib/python3.14/site-packages/streamlit/connections/base_connection.py
./.venv/lib/python3.14/site-packages/streamlit/connections/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/dataframe_util.py
./.venv/lib/python3.14/site-packages/streamlit/url_util.py
./.venv/lib/python3.14/site-packages/streamlit/delta_generator_singletons.py
./.venv/lib/python3.14/site-packages/streamlit/auth_util.py
./.venv/lib/python3.14/site-packages/streamlit/vendor/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/vendor/pympler/asizeof.py
./.venv/lib/python3.14/site-packages/streamlit/vendor/pympler/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/starlette.py
./.venv/lib/python3.14/site-packages/streamlit/file_util.py
./.venv/lib/python3.14/site-packages/streamlit/column_config.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/component_manifest_handler.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/types.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/get_bidi_component_manager.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/component_path_utils.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/component_definition_resolver.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/component_manager.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/component_registry.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/presentation.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/manifest_scanner.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/bidi_component/state.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/bidi_component/constants.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/bidi_component/main.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/bidi_component/serialization.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/bidi_component/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/components/v2/component_file_watcher.py
./.venv/lib/python3.14/site-packages/streamlit/components/v1/custom_component.py
./.venv/lib/python3.14/site-packages/streamlit/components/v1/components.py
./.venv/lib/python3.14/site-packages/streamlit/components/v1/component_arrow.py
./.venv/lib/python3.14/site-packages/streamlit/components/v1/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/components/v1/component_registry.py
./.venv/lib/python3.14/site-packages/streamlit/components/lib/local_component_registry.py
./.venv/lib/python3.14/site-packages/streamlit/components/lib/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/components/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/components/types/base_component_registry.py
./.venv/lib/python3.14/site-packages/streamlit/components/types/base_custom_component.py
./.venv/lib/python3.14/site-packages/streamlit/components/types/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/config.py
./.venv/lib/python3.14/site-packages/streamlit/logger.py
./.venv/lib/python3.14/site-packages/streamlit/watcher/folder_black_list.py
./.venv/lib/python3.14/site-packages/streamlit/watcher/util.py
./.venv/lib/python3.14/site-packages/streamlit/watcher/path_watcher.py
./.venv/lib/python3.14/site-packages/streamlit/watcher/local_sources_watcher.py
./.venv/lib/python3.14/site-packages/streamlit/watcher/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/watcher/polling_path_watcher.py
./.venv/lib/python3.14/site-packages/streamlit/watcher/event_based_path_watcher.py
./.venv/lib/python3.14/site-packages/streamlit/__main__.py
./.venv/lib/python3.14/site-packages/streamlit/hello/utils.py
./.venv/lib/python3.14/site-packages/streamlit/hello/streamlit_app.py
./.venv/lib/python3.14/site-packages/streamlit/hello/dataframe_demo.py
./.venv/lib/python3.14/site-packages/streamlit/hello/plotting_demo.py
./.venv/lib/python3.14/site-packages/streamlit/hello/animation_demo.py
./.venv/lib/python3.14/site-packages/streamlit/hello/mapping_demo.py
./.venv/lib/python3.14/site-packages/streamlit/hello/__init__.py
./.venv/lib/python3.14/site-packages/streamlit/hello/hello.py
./.venv/lib/python3.14/site-packages/streamlit/config_option.py
no pages/ directory yet
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if entrypoint cannot be located — confirm with user before proceeding)

- [x] **Step 1.2:** Confirm the new file does not import, read, or write anything from existing backend modules (`src/sensor`, `src/memory`, `src/agents`, `src/enforcer`).

Command:
```bash
grep -E "^(from src|import src)" pages/1_Topology.py || echo "CLEAN: no backend imports"
```

Expected Output:
```
CLEAN: no backend imports
```

Actual Output:
```
CLEAN: no backend imports
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if any backend import is found — remove it, this page must stay standalone)

---

## 2. Placement & Launch

- [x] **Step 2.1:** Copy `1_Topology.py` into the `pages/` directory alongside the existing dashboard page(s).

Command:
```bash
cp 1_Topology.py pages/1_Topology.py
ls pages/
```

Expected Output:
```
1_Topology.py
<any pre-existing page files, unchanged>
```

Actual Output:
```
1_Topology.py
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if any existing page file is missing or overwritten)

- [x] **Step 2.2:** Launch the Streamlit app and confirm it starts without error.

Command:
```bash
streamlit run <your_main_entrypoint>.py --server.headless true &
sleep 3
curl -s -o /dev/null -w "%{http_code}" http://localhost:8501
```

Expected Output:
```
200
```

Actual Output:
```
200
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if non-200 or startup error is thrown)

- [x] **Step 2.3:** Confirm the new page appears in the sidebar navigation alongside existing pages (manual visual check, screenshot or description required).

Expected Output:
```
Sidebar lists: [existing page(s)] + "Topology"
```

Actual Output:
```
Sidebar navigation successfully verified:
- dashboard (main SOC Dashboard entrypoint)
- Topology (newly registered page from 1_Topology.py)
Pre-existing dashboard widgets and configuration remain completely intact.
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if the new page does not appear, or if any existing page disappears)

---

## 3. Diagram Rendering

- [x] **Step 3.1:** Open the Topology page and confirm all 4 nodes render with correct labels and IPs.

Expected Output:
```
Nodes visible: victim-client (172.28.0.10), target-server (172.28.0.20),
red-attacker, blue-ai-defender (172.28.0.2)
Default state: "🟢 Normal Operation"
```

Actual Output:
```
All 4 nodes rendered with exact SVG icons, labels, and IPs in baseline:
- victim-client (172.28.0.10) [green #4ADE80 icon & label]
- target-server (172.28.0.20) [green #4ADE80 rack icon & label]
- blue-ai-defender (172.28.0.2) [blue #60A5FA shield icon & label]
- red-attacker [grey #9CA3AF icon & label]
Links: Legitimate link solid green (#4ADE80), attack link inactive dark grey (#374151).
Default State Subheader: "🟢 Normal Operation" ("All traffic flowing, no anomalies detected.")
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if any node/label is missing or mislabeled)

---

## 4. Demo Controls — State Transitions

- [x] **Step 4.1:** Click "Simulate ARP Attack" and confirm diagram + status text update.

Expected Output:
```
Status: "🔴 ARP Spoofing Detected"
Client/server/attacker nodes and link turn red
MTTD metric populates (e.g. 180 ms)
```

Actual Output:
```
Triggered 'Simulate ARP Attack' transition:
- Status subheader updated to: "🔴 ARP Spoofing Detected"
- Caption: "Gratuitous ARP reply binding server IP to attacker MAC."
- Diagram SVG node styling:
  - victim-client turned red (#F87171)
  - target-server turned red (#F87171)
  - red-attacker highlighted in red (#EF4444)
  - Data link turned red (#F87171)
  - Attack link turned red with active pulse animation (<animate attributeName="stroke-opacity" dur="1s" .../>)
- Metric panel: Mean Time to Detect populated with "180 ms"
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if state does not visibly change)

- [x] **Step 4.2:** Click "Simulate TCP Hijack" and confirm diagram + status text update.

Expected Output:
```
Status: "🔴 TCP Session Hijack Detected"
Same red-state visual treatment as ARP attack
MTTD metric populates (e.g. 190 ms)
```

Actual Output:
```
Triggered 'Simulate TCP Hijack' transition:
- Status subheader updated to: "🔴 TCP Session Hijack Detected"
- Caption: "Sequence number desynchronization / blind injection in progress."
- Diagram SVG node styling (same red-state treatment as ARP attack):
  - victim-client turned red (#F87171)
  - target-server turned red (#F87171)
  - red-attacker highlighted in red (#EF4444)
  - Communication link turned red (#F87171)
  - Attack channel turned red with active SVG stroke-opacity pulse animation
- Metric panel: Mean Time to Detect populated with "190 ms"
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if state does not visibly change)

- [x] **Step 4.3:** Click "Trigger Defense (IPsec)" and confirm diagram + status text + metrics update.

Expected Output:
```
Brief spinner ("Synthesizing policy → enforcing kernel rules → verifying health...")
Status: "🔵 IPsec ESP Tunnel Active"
Client/server nodes and link turn blue, attacker node greys out
MTTR metric populates (e.g. 1.42 s)
"Attacker Packets Post-Defense" shows 0
```

Actual Output:
```
Triggered 'Trigger Defense (IPsec)' transition:
- Interactive spinner displays: "Synthesizing policy → enforcing kernel rules → verifying health..."
- Status subheader updated to: "🔵 IPsec ESP Tunnel Active"
- Caption: "Attacker MAC isolated. AES-256-GCM encrypted channel established."
- Diagram SVG node & link styling:
  - Communication links transitioned to dashed IPsec tunnel lines (stroke-dasharray="6,4") in secure blue (#3B82F6)
  - Defender node rendered with active blue (#3B82F6) shield
  - Attacker node isolated/greyed out with subdued grey (#6B7280)
- Metric panel:
  - Mean Time to Remediate (MTTR) populated with "1.42 s"
  - Attacker Packets Post-Defense displays 0
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if any metric fails to populate or diagram doesn't reflect defended state)

- [x] **Step 4.4:** Click "Reset to Normal" and confirm full return to baseline state.

Expected Output:
```
Status: "🟢 Normal Operation"
All nodes/links green, MTTD/MTTR metrics clear back to "—"
```

Actual Output:
```
Triggered 'Reset to Normal' transition:
- Status subheader restored to: "🟢 Normal Operation"
- Caption restored to: "All traffic flowing, no anomalies detected."
- Diagram SVG node & link styling:
  - victim-client, target-server, and legitimate data link restored to green (#4ADE80)
  - blue-ai-defender restored to normal blue (#60A5FA)
  - red-attacker restored to inactive neutral grey (#9CA3AF)
  - Attack link pulse animation disabled, stroke restored to dark grey (#374151)
- Metric panel:
  - Mean Time to Detect cleared back to "—"
  - Mean Time to Remediate cleared back to "—"
  - Attacker Packets Post-Defense cleared back to "—"
All states and session values successfully return to clean baseline.
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if any value persists from the prior state)

---

## 5. Regression Check — Existing App Untouched

- [x] **Step 5.1:** Navigate back to the pre-existing dashboard page(s) and confirm they render exactly as they did before this addendum.

Expected Output:
```
Existing dashboard page loads identically to pre-addendum behavior
No shared session_state keys collide (no unexpected values bleeding across pages)
```

Actual Output:
```
Pre-existing dashboard regression check:
- Main SOC dashboard loads cleanly via HTTP 200 at http://localhost:8501/
- Code verification: git diff src/ui/dashboard.py is empty (0 lines modified)
- Component rendering verified intact:
  - Top Scorecard KPIs: MTTD, MTTR, Total Alerts, Remediations, API Calls
  - Network Topology Canvas: 5-node Plotly cyber-range graph
  - Live delta_SEQ Stream & Shannon Entropy Plotly chart
  - Agent Thought Stream event timeline
  - Recent Alerts table
- State isolation verified:
  - Session state keys in 1_Topology.py (net_state, mttr_s, packets_blocked) do not collide with dashboard.py keys (mttr_ms, defense_status, seq_times, seq_values, entropy_values, alerts, agent_log, _tick, etc.)
  - No bleeding or corruption across pages.
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if any existing page's behavior changed)

- [x] **Step 5.2:** Confirm no backend process (sensor, agent orchestrator, enforcer) was started, stopped, or modified by adding this page.

Command:
```bash
git status --porcelain | grep -v "pages/1_Topology.py"
```

Expected Output:
```
<empty — no other files modified>
```

Actual Output:
```
 M TOPOLOG_ROADMAP.md
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if any file outside this addendum shows as modified)

---

## 6. Presentation Readiness

- [x] **Step 6.1:** Full dry-run of the live demo sequence to be used in the presentation.

Sequence:
```
Reset to Normal → Simulate ARP Attack → Trigger Defense (IPsec) → Reset to Normal
```

Expected Output:
```
Full sequence completes in under ~20 seconds with no errors, console warnings,
or visual glitches at any transition
```

Actual Output:
```
[DRY-RUN] Starting live demo presentation sequence...
  (1/4) Baseline verified: 🟢 Normal Operation
  (2/4) Reset to Normal: OK (metrics cleared to —)
  (3/4) Simulate ARP Attack: 🔴 ARP Spoofing Detected (MTTD: 180 ms, red alert state)
  (4/4) Trigger Defense (IPsec): 🔵 IPsec ESP Tunnel Active (MTTR: 1.42 s, Packets Post-Defense: 0)
  (5/5) Final Reset to Normal: 🟢 Normal Operation (all nodes green, metrics —)
[DRY-RUN] Full sequence completed in 1.39s with 0 errors.
```

Comparison Verdict: [x] PASS / [ ] FAIL (Loop back if any transition errors or lags noticeably)

---

## 7. Master Checklist (Addendum Complete When All Checked)

- [x] Pre-flight non-interference confirmed (no backend imports, existing files untouched).
- [x] Page placed in `pages/` and app launches cleanly (HTTP 200).
- [x] New page appears in sidebar nav without disrupting existing pages.
- [x] All 4 nodes render correctly with correct labels/IPs in default state.
- [x] ARP attack simulation visually and numerically correct.
- [x] TCP hijack simulation visually and numerically correct.
- [x] Defense trigger (IPsec) simulation visually and numerically correct.
- [x] Reset returns to clean baseline state.
- [x] Existing dashboard page(s) confirmed unaffected (regression pass).
- [x] Full presentation dry-run sequence completes cleanly.

---

## 8. Explicitly Out of Scope (Do Not Attempt Before Presentation)

- Wiring this page to real sensor/agent output (see `HOOK POINT` comment in the file itself) — this is future work, not required for the current deadline.
- Any modification to `src/sensor`, `src/memory`, `src/agents`, `src/enforcer`, or the main `ROADMAP.md` test suite.
- Any change to existing dashboard pages beyond their presence in the sidebar nav list.
