/**
\brief Declaration of the "opentimers" driver.

\author Tengfei Chang <tengfei.chang@inria.fr>, April 2017.
*/

#ifndef OPENTIMERS_OPENTIMERS_H
#define OPENTIMERS_OPENTIMERS_H

#include "opendefs.h"

/**
\addtogroup drivers
\{
\addtogroup OpenTimers
\{
*/

//=========================== define ==========================================

/// Maximum number of timers that can run concurrently
#define MAX_NUM_TIMERS             15
#define MAX_TICKS_IN_SINGLE_CLOCK  (uint32_t)(((PORT_TIMER_WIDTH)0xFFFFFFFF)>>1)
#define ERROR_NO_AVAILABLE_ENTRIES 255
#define MAX_DURATION_ISR           33 // 33@32768Hz = 1ms
#define opentimers_id_t            uint8_t

#define TIMER_INHIBIT              0
#define TIMER_TSCH                 1
#define TIMER_GENERAL_PURPOSE      255

#define TIMER_NUMBER_NON_GENERAL   2

#define SPLITE_TIMER_DURATION     15 // in ticks
#define PRE_CALL_TIMER_WINDOW     PORT_TsSlotDuration

typedef void (*opentimers_cbt)(void *arg);

//=========================== typedef =========================================

typedef enum {
    TIMER_PERIODIC,
    TIMER_ONESHOT,
} timer_type_t;

typedef enum {
    TIME_MS,
    TIME_TICS,
} time_type_t;

typedef struct {
    uint8_t timer_id;                           // timer id
    uint32_t duration;                          // the duration that set by timer, in ticks
    PORT_TIMER_WIDTH currentCompareValue;       // the current compare value
    uint16_t wraps_remaining;                   // the number of wraps timer is going to be fired after
    PORT_TIMER_WIDTH lastCompareValue;          // the previous compare value
    bool isRunning;                             // is running?
    bool isUsed;                                // true when this entry is occupied
    timer_type_t timerType;                     // the timer type
    bool hasExpired;                            // in case there are more than one interrupt occur at same time
    opentimers_cbt callback;                    // function to call when elapses
    uint8_t timer_task_prio;                    // when opentimer push a task, use timer_task_prio to mark the priority
} opentimers_t;

//=========================== module variables ================================

typedef struct {
    opentimers_t timersBuf[MAX_NUM_TIMERS];
    bool running;
    PORT_TIMER_WIDTH currentCompareValue;   // current timeout, in ticks
    PORT_TIMER_WIDTH lastCompareValue;      // last timeout, in ticks. This is the reference time to calculate the next to be expired timer.
    bool insideISR;                         // whether the function of opentimer is called inside of ISR or not
} opentimers_vars_t;

//=========================== prototypes ======================================

/**
\brief Initialize this module.

Initializes data structures and hardware timer.
 */
void opentimers_init(void);

/**
\brief create a timer by assigning an entry from timer buffer.

create a timer with given id or assigning one if it's general purpose timer.
task_prio gives a priority when opentimer push a task.

\returns the id of the timer will be returned
 */
opentimers_id_t opentimers_create(uint8_t timer_id, uint8_t task_priority);

/**
\brief schedule a period refer to comparing value set last time.

This function will schedule a timer which expires when the timer count reach
to current counter + duration.

\param[in] id indicates the timer id
\param[in] duration indicates the period asked for schedule since last comparing value
\param[in] uint_type indicates the unit type of this schedule: ticks or ms
\param[in] timer_type indicates the timer type of this schedule: oneshot or periodic
\param[in] cb indicates when this scheduled timer fired, call this callback function.
 */
void opentimers_scheduleIn(opentimers_id_t id,
                           uint32_t duration,
                           time_type_t uint_type,
                           timer_type_t timer_type,
                           opentimers_cbt cb);

/**
\brief schedule a period refer to given reference.

This function will schedule a timer which expires when the timer count reach
to duration + reference. This function will be used in the implementation of slot FSM.
All timers use this function are ONE_SHOT type timer.

\param[in] id indicates the timer id
\param[in] duration indicates the period asked for schedule after a given time indicated by reference parameter.
\param[in] reference indicates the reference for duration. The timer will be fired at reference+duration.
\param[in] uint_type indicates the unit type of this schedule: ticks or ms
\param[in] cb indicates when this scheduled timer fired, call this callback function.
 */
void opentimers_scheduleAbsolute(opentimers_id_t id,
                                 uint32_t duration,
                                 PORT_TIMER_WIDTH reference,
                                 time_type_t uint_type,
                                 opentimers_cbt cb);

/**
\brief update the duration of timer.

This function should be called in the callback of the timer interrupt.

\param[in] id the timer id
\param[in] duration the timer duration
 */
void opentimers_updateDuration(opentimers_id_t id, PORT_TIMER_WIDTH duration);

/**
\brief cancel a running timer.

This function disable the timer temperally by removing its callback and marking
isRunning as false. The timer may be recover later.

\param[in] id the timer id
 */
void opentimers_cancel(opentimers_id_t id);

/**
\brief destroy a stored timer.

Reset the whole entry of given timer including the id.

\param[in] id the timer id

\returns False if the given can't be found or return Success
 */
bool opentimers_destroy(opentimers_id_t id);

/**
\brief get the current counter value of sctimer.

\returns the current counter value.
 */
PORT_TIMER_WIDTH opentimers_getValue(void);

/**
\brief get the currentCompareValue variable of opentimer2.

\returns currentCompareValue.
 */
PORT_TIMER_WIDTH opentimers_getCurrentCompareValue(void);

/**
\brief is the given timer running?

\returns isRunning variable.
 */
bool opentimers_isRunning(opentimers_id_t id);
/**
\}
\}
*/

#endif