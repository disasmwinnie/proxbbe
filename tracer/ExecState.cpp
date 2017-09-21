#include "ExecState.h"

ExecState::ExecState(const std::string ip, const enum _state_type st)
    : _ip(ip), _st(st) {};

ExecState::~ExecState() {};

std::string ExecState::dump_data() {return "ExecState should not be used!";};
